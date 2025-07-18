// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Feature Activations
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FeatureActivations {
    /// Enables the Input Prepare feature. You can create Input Prepare actions in the schedule only if this feature is enabled. If you disable the feature on an existing schedule, make sure that you first delete all input prepare actions from the schedule.
    pub input_prepare_schedule_actions: ::std::option::Option<crate::types::FeatureActivationsInputPrepareScheduleActions>,
    /// Enables the output static image overlay feature. Enabling this feature allows you to send channel schedule updates to display/clear/modify image overlays on an output-by-output bases.
    pub output_static_image_overlay_schedule_actions: ::std::option::Option<crate::types::FeatureActivationsOutputStaticImageOverlayScheduleActions>,
}
impl FeatureActivations {
    /// Enables the Input Prepare feature. You can create Input Prepare actions in the schedule only if this feature is enabled. If you disable the feature on an existing schedule, make sure that you first delete all input prepare actions from the schedule.
    pub fn input_prepare_schedule_actions(&self) -> ::std::option::Option<&crate::types::FeatureActivationsInputPrepareScheduleActions> {
        self.input_prepare_schedule_actions.as_ref()
    }
    /// Enables the output static image overlay feature. Enabling this feature allows you to send channel schedule updates to display/clear/modify image overlays on an output-by-output bases.
    pub fn output_static_image_overlay_schedule_actions(
        &self,
    ) -> ::std::option::Option<&crate::types::FeatureActivationsOutputStaticImageOverlayScheduleActions> {
        self.output_static_image_overlay_schedule_actions.as_ref()
    }
}
impl FeatureActivations {
    /// Creates a new builder-style object to manufacture [`FeatureActivations`](crate::types::FeatureActivations).
    pub fn builder() -> crate::types::builders::FeatureActivationsBuilder {
        crate::types::builders::FeatureActivationsBuilder::default()
    }
}

/// A builder for [`FeatureActivations`](crate::types::FeatureActivations).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FeatureActivationsBuilder {
    pub(crate) input_prepare_schedule_actions: ::std::option::Option<crate::types::FeatureActivationsInputPrepareScheduleActions>,
    pub(crate) output_static_image_overlay_schedule_actions:
        ::std::option::Option<crate::types::FeatureActivationsOutputStaticImageOverlayScheduleActions>,
}
impl FeatureActivationsBuilder {
    /// Enables the Input Prepare feature. You can create Input Prepare actions in the schedule only if this feature is enabled. If you disable the feature on an existing schedule, make sure that you first delete all input prepare actions from the schedule.
    pub fn input_prepare_schedule_actions(mut self, input: crate::types::FeatureActivationsInputPrepareScheduleActions) -> Self {
        self.input_prepare_schedule_actions = ::std::option::Option::Some(input);
        self
    }
    /// Enables the Input Prepare feature. You can create Input Prepare actions in the schedule only if this feature is enabled. If you disable the feature on an existing schedule, make sure that you first delete all input prepare actions from the schedule.
    pub fn set_input_prepare_schedule_actions(
        mut self,
        input: ::std::option::Option<crate::types::FeatureActivationsInputPrepareScheduleActions>,
    ) -> Self {
        self.input_prepare_schedule_actions = input;
        self
    }
    /// Enables the Input Prepare feature. You can create Input Prepare actions in the schedule only if this feature is enabled. If you disable the feature on an existing schedule, make sure that you first delete all input prepare actions from the schedule.
    pub fn get_input_prepare_schedule_actions(&self) -> &::std::option::Option<crate::types::FeatureActivationsInputPrepareScheduleActions> {
        &self.input_prepare_schedule_actions
    }
    /// Enables the output static image overlay feature. Enabling this feature allows you to send channel schedule updates to display/clear/modify image overlays on an output-by-output bases.
    pub fn output_static_image_overlay_schedule_actions(
        mut self,
        input: crate::types::FeatureActivationsOutputStaticImageOverlayScheduleActions,
    ) -> Self {
        self.output_static_image_overlay_schedule_actions = ::std::option::Option::Some(input);
        self
    }
    /// Enables the output static image overlay feature. Enabling this feature allows you to send channel schedule updates to display/clear/modify image overlays on an output-by-output bases.
    pub fn set_output_static_image_overlay_schedule_actions(
        mut self,
        input: ::std::option::Option<crate::types::FeatureActivationsOutputStaticImageOverlayScheduleActions>,
    ) -> Self {
        self.output_static_image_overlay_schedule_actions = input;
        self
    }
    /// Enables the output static image overlay feature. Enabling this feature allows you to send channel schedule updates to display/clear/modify image overlays on an output-by-output bases.
    pub fn get_output_static_image_overlay_schedule_actions(
        &self,
    ) -> &::std::option::Option<crate::types::FeatureActivationsOutputStaticImageOverlayScheduleActions> {
        &self.output_static_image_overlay_schedule_actions
    }
    /// Consumes the builder and constructs a [`FeatureActivations`](crate::types::FeatureActivations).
    pub fn build(self) -> crate::types::FeatureActivations {
        crate::types::FeatureActivations {
            input_prepare_schedule_actions: self.input_prepare_schedule_actions,
            output_static_image_overlay_schedule_actions: self.output_static_image_overlay_schedule_actions,
        }
    }
}
