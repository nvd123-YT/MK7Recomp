//! game controllers, any the system knows, read through gilrs, and the
//! Switch's Pro Controller on macOS read from its reports, see
//! pro_controller.

use gilrs::{Axis, Button, EventType, Gamepad, Gilrs};
use gilrs::ev::Code;
use zakuro_core::services::hid::{InputState, PadState};

use crate::pro_controller::{is_pro_controller, Controllers, Report};
use crate::settings::{PadButtons, PedalAxisRange, WheelSettings};

/// how far a stick has to lean before it counts, some rest a little off
/// center.
const DEADZONE: f32 = 0.15;

/// An axis movement captured from a physical controller or wheel.
#[derive(Debug, Clone)]
pub struct AxisInput {
    pub device_id: [u8; 16],
    pub device_name: String,
    pub code: Code,
}

pub struct Gamepads {
    /// none when the system could not be asked for controllers.
    gilrs: Option<Gilrs>,
    buttons: PadButtons,
    axis_event: Option<AxisInput>,
    /// Pro Controllers read from their own reports, on macOS.
    pro: Controllers,
    /// the buttons they held at the last poll, to tell the ones pressed
    /// since.
    pro_held: Vec<Button>,
}

/// whether gilrs's reading of a controller is left out, a Pro Controller's
/// while one is read from its reports.
fn left_out(pad: &Gamepad, reports: &[std::sync::Arc<Report>]) -> bool {
    !reports.is_empty() && is_pro_controller(pad.vendor_id(), pad.product_id(), pad.name())
}

impl Gamepads {
    pub fn new(buttons: PadButtons) -> Gamepads {
        let gilrs = Gilrs::new()
            .inspect_err(|error| log::warn!("controllers are not available, {error}"))
            .ok();
        Gamepads { gilrs, buttons, axis_event: None, pro: Controllers::new(), pro_held: Vec::new() }
    }

    pub fn set_buttons(&mut self, buttons: PadButtons) {
        self.buttons = buttons;
    }

    /// takes in what the controllers did since the last call, and returns the
    /// buttons pressed meanwhile.
    pub fn poll(&mut self) -> Vec<Button> {
        let mut pressed = Vec::new();
        self.axis_event = None;
        let reports = self.pro.reports();
        if let Some(gilrs) = &mut self.gilrs {
            while let Some(event) = gilrs.next_event() {
                match event.event {
                    EventType::ButtonPressed(button, _) if !left_out(&gilrs.gamepad(event.id), &reports) => pressed.push(button),
                    EventType::AxisChanged(_, value, code) => {
                        let pad = gilrs.gamepad(event.id);
                        // Keep native axis codes so wheels with unmapped steering
                        // and pedal axes can still be configured.
                        if !left_out(&pad, &reports) && value.abs() >= 0.20 {
                            self.axis_event = Some(AxisInput {
                                device_id: pad.uuid(),
                                device_name: pad.name().to_owned(),
                                code,
                            });
                        }
                    }
                    EventType::Connected => {
                        log::info!("controller connected, {}", gilrs.gamepad(event.id).name());
                    }
                    EventType::Disconnected => log::info!("controller disconnected"),
                    _ => {}
                }
            }
        }
        let held: Vec<Button> = reports.iter().flat_map(|report| report.buttons.iter().copied()).collect();
        pressed.extend(held.iter().filter(|button| !self.pro_held.contains(button)));
        self.pro_held = held;
        pressed
    }

    pub fn take_axis(&mut self) -> Option<AxisInput> {
        self.axis_event.take()
    }

    /// whether a controller holds button down.
    pub fn holding(&self, button: Button) -> bool {
        let reports = self.pro.reports();
        reports.iter().any(|report| report.buttons.contains(&button))
            || self.gilrs.as_ref().is_some_and(|gilrs| {
                gilrs.gamepads().any(|(_, pad)| !left_out(&pad, &reports) && pad.is_pressed(button))
            })
    }

    /// what the controllers hold down, over what the keyboard does.
    pub fn apply(&self, mut state: InputState, wheel: &WheelSettings) -> InputState {
        let reports = self.pro.reports();
        for report in &reports {
            for (button, bound) in self.buttons.map() {
                if report.buttons.contains(&bound) {
                    state.buttons.set(button, true);
                }
            }
            sticks(&mut state, report.left, report.right);
        }
        let Some(gilrs) = &self.gilrs else { return state };
        for (_, pad) in gilrs.gamepads() {
            if left_out(&pad, &reports) {
                continue;
            }
            for (button, bound) in self.buttons.map() {
                if pad.is_pressed(bound) {
                    state.buttons.set(button, true);
                }
            }
            // the d-pad of some controllers is a pair of axes
            let dpad = [
                (PadState::RIGHT, pad.value(Axis::DPadX) > 0.5),
                (PadState::LEFT, pad.value(Axis::DPadX) < -0.5),
                (PadState::UP, pad.value(Axis::DPadY) > 0.5),
                (PadState::DOWN, pad.value(Axis::DPadY) < -0.5),
            ];
            for (button, held) in dpad {
                if held {
                    state.buttons.set(button, true);
                }
            }
            let left = [pad.value(Axis::LeftStickX), pad.value(Axis::LeftStickY)];
            let right = [pad.value(Axis::RightStickX), pad.value(Axis::RightStickY)];
            sticks(&mut state, left, right);

            if wheel.enabled {
                apply_wheel(&mut state, &pad, wheel);
            }
        }
        state
    }
}

fn apply_wheel(state: &mut InputState, pad: &Gamepad, wheel: &WheelSettings) {
    let device_id = pad.uuid();
    let uses_device = |specific: Option<&[u8; 16]>| {
        specific.or(wheel.device_id.as_ref()) == Some(&device_id)
    };

    if uses_device(wheel.steering_device_id.as_ref()) {
        if let Some(code) = wheel.steering {
            let mut value = pad.state().value(code).clamp(-1.0, 1.0);
            if wheel.steering_inverted {
                value = -value;
            }
            let deadzone = f32::from(wheel.steering_deadzone.min(35)) / 100.0;
            let magnitude = value.abs();
            state.circle_x = if magnitude <= deadzone {
                0.0
            } else {
                value.signum() * ((magnitude - deadzone) / (1.0 - deadzone)).clamp(0.0, 1.0)
            };
        }
    }

    let pedal_pressed = |code: Option<Code>, inverted: bool| -> bool {
        let Some(code) = code else { return false };
        let raw = pad.state().value(code).clamp(-1.0, 1.0);
        let mut value = match wheel.pedal_axis_range {
            PedalAxisRange::NegativeToPositive => (raw + 1.0) * 0.5,
            PedalAxisRange::ZeroToOne => raw.max(0.0),
        };
        if inverted {
            value = 1.0 - value;
        }
        value >= 0.5
    };
    if uses_device(wheel.accelerator_device_id.as_ref())
        && pedal_pressed(wheel.accelerator, wheel.accelerator_inverted)
    {
        state.buttons.insert(PadState::A);
    }
    if uses_device(wheel.brake_device_id.as_ref())
        && pedal_pressed(wheel.brake, wheel.brake_inverted)
    {
        state.buttons.insert(PadState::B);
    }
}

/// the left stick is the circle pad and the right one the C-stick, up
/// positive as the console has it, each once it leans past the deadzone.
fn deadzone_pair([x, y]: [f32; 2]) -> Option<[f32; 2]> {
    let x = x.clamp(-1.0, 1.0);
    let y = y.clamp(-1.0, 1.0);
    let magnitude = x.hypot(y);
    if magnitude <= DEADZONE {
        return None;
    }
    let scaled = ((magnitude - DEADZONE) / (1.0 - DEADZONE)).min(1.0);
    let factor = scaled / magnitude;
    Some([x * factor, y * factor])
}

fn sticks(state: &mut InputState, [x, y]: [f32; 2], [cx, cy]: [f32; 2]) {
    if let Some([x, y]) = deadzone_pair([x, y]) {
        state.circle_x = x;
        state.circle_y = y;
    }
    if let Some([cx, cy]) = deadzone_pair([cx, cy]) {
        state.c_stick_x = cx;
        state.c_stick_y = cy;
    }
}

/// a controller button as a person would call it.
pub fn button_name(button: Button) -> &'static str {
    match button {
        Button::South => "Bottom face",
        Button::East => "Right face",
        Button::North => "Top face",
        Button::West => "Left face",
        Button::LeftTrigger => "LB / L1",
        Button::RightTrigger => "RB / R1",
        Button::LeftTrigger2 => "LT / L2",
        Button::RightTrigger2 => "RT / R2",
        Button::Select => "Back / Select",
        Button::Start => "Start",
        Button::Mode => "Home",
        Button::LeftThumb => "Left stick",
        Button::RightThumb => "Right stick",
        Button::DPadUp => "D-pad up",
        Button::DPadDown => "D-pad down",
        Button::DPadLeft => "D-pad left",
        Button::DPadRight => "D-pad right",
        Button::C => "C",
        Button::Z => "Z",
        Button::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// with no controller, or no way to ask for one, the keyboard's input
    /// goes through as it was.
    #[test]
    fn radial_deadzone_filters_jitter_and_preserves_full_travel() {
        assert_eq!(deadzone_pair([0.10, 0.0]), None);
        let half = deadzone_pair([0.575, 0.0]).unwrap();
        assert!((half[0] - 0.5).abs() < 0.001);
        let full = deadzone_pair([1.0, 0.0]).unwrap();
        assert!((full[0] - 1.0).abs() < 0.001);
    }

    #[test]
    fn no_controller_leaves_the_keyboard_alone() {
        let gamepads = Gamepads::new(PadButtons::default());
        if gamepads.gilrs.as_ref().is_some_and(|gilrs| gilrs.gamepads().next().is_some()) {
            return;
        }
        let state = InputState { buttons: PadState::A, circle_x: 1.0, circle_y: 0.0, touch: Some((1, 2)), ..InputState::default() };
        let applied = gamepads.apply(state, &WheelSettings::default());
        assert_eq!(applied.buttons, PadState::A);
        assert_eq!((applied.circle_x, applied.circle_y, applied.touch), (1.0, 0.0, Some((1, 2))));
    }
}
