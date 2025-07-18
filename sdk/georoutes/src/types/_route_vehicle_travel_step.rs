// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Steps of a leg that correspond to the travel portion of the leg.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteVehicleTravelStep {
    /// <p>Details that are specific to a Continue Highway step.</p>
    pub continue_highway_step_details: ::std::option::Option<crate::types::RouteContinueHighwayStepDetails>,
    /// <p>Details that are specific to a Continue step.</p>
    pub continue_step_details: ::std::option::Option<crate::types::RouteContinueStepDetails>,
    /// <p>Details of the current road.</p>
    pub current_road: ::std::option::Option<crate::types::RouteRoad>,
    /// <p>Distance of the step.</p>
    pub distance: i64,
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub duration: i64,
    /// <p>Details that are specific to a Enter Highway step.</p>
    pub enter_highway_step_details: ::std::option::Option<crate::types::RouteEnterHighwayStepDetails>,
    /// <p>Exit number of the road exit, if applicable.</p>
    pub exit_number: ::std::option::Option<::std::vec::Vec<crate::types::LocalizedString>>,
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub exit_step_details: ::std::option::Option<crate::types::RouteExitStepDetails>,
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub geometry_offset: ::std::option::Option<i32>,
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub instruction: ::std::option::Option<::std::string::String>,
    /// <p>Details that are specific to a Keep step.</p>
    pub keep_step_details: ::std::option::Option<crate::types::RouteKeepStepDetails>,
    /// <p>Details of the next road. See RouteRoad for details of sub-attributes.</p>
    pub next_road: ::std::option::Option<crate::types::RouteRoad>,
    /// <p>Details that are specific to a Ramp step.</p>
    pub ramp_step_details: ::std::option::Option<crate::types::RouteRampStepDetails>,
    /// <p>Details that are specific to a Roundabout Enter step.</p>
    pub roundabout_enter_step_details: ::std::option::Option<crate::types::RouteRoundaboutEnterStepDetails>,
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub roundabout_exit_step_details: ::std::option::Option<crate::types::RouteRoundaboutExitStepDetails>,
    /// <p>Details that are specific to a Roundabout Pass step.</p>
    pub roundabout_pass_step_details: ::std::option::Option<crate::types::RouteRoundaboutPassStepDetails>,
    /// <p>Sign post information of the action, applicable only for TurnByTurn steps. See RouteSignpost for details of sub-attributes.</p>
    pub signpost: ::std::option::Option<crate::types::RouteSignpost>,
    /// <p>Details that are specific to a Turn step.</p>
    pub turn_step_details: ::std::option::Option<crate::types::RouteTurnStepDetails>,
    /// <p>Type of the step.</p>
    pub r#type: crate::types::RouteVehicleTravelStepType,
    /// <p>Details that are specific to a Turn step.</p>
    pub u_turn_step_details: ::std::option::Option<crate::types::RouteUTurnStepDetails>,
}
impl RouteVehicleTravelStep {
    /// <p>Details that are specific to a Continue Highway step.</p>
    pub fn continue_highway_step_details(&self) -> ::std::option::Option<&crate::types::RouteContinueHighwayStepDetails> {
        self.continue_highway_step_details.as_ref()
    }
    /// <p>Details that are specific to a Continue step.</p>
    pub fn continue_step_details(&self) -> ::std::option::Option<&crate::types::RouteContinueStepDetails> {
        self.continue_step_details.as_ref()
    }
    /// <p>Details of the current road.</p>
    pub fn current_road(&self) -> ::std::option::Option<&crate::types::RouteRoad> {
        self.current_road.as_ref()
    }
    /// <p>Distance of the step.</p>
    pub fn distance(&self) -> i64 {
        self.distance
    }
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn duration(&self) -> i64 {
        self.duration
    }
    /// <p>Details that are specific to a Enter Highway step.</p>
    pub fn enter_highway_step_details(&self) -> ::std::option::Option<&crate::types::RouteEnterHighwayStepDetails> {
        self.enter_highway_step_details.as_ref()
    }
    /// <p>Exit number of the road exit, if applicable.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.exit_number.is_none()`.
    pub fn exit_number(&self) -> &[crate::types::LocalizedString] {
        self.exit_number.as_deref().unwrap_or_default()
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn exit_step_details(&self) -> ::std::option::Option<&crate::types::RouteExitStepDetails> {
        self.exit_step_details.as_ref()
    }
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn geometry_offset(&self) -> ::std::option::Option<i32> {
        self.geometry_offset
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn instruction(&self) -> ::std::option::Option<&str> {
        self.instruction.as_deref()
    }
    /// <p>Details that are specific to a Keep step.</p>
    pub fn keep_step_details(&self) -> ::std::option::Option<&crate::types::RouteKeepStepDetails> {
        self.keep_step_details.as_ref()
    }
    /// <p>Details of the next road. See RouteRoad for details of sub-attributes.</p>
    pub fn next_road(&self) -> ::std::option::Option<&crate::types::RouteRoad> {
        self.next_road.as_ref()
    }
    /// <p>Details that are specific to a Ramp step.</p>
    pub fn ramp_step_details(&self) -> ::std::option::Option<&crate::types::RouteRampStepDetails> {
        self.ramp_step_details.as_ref()
    }
    /// <p>Details that are specific to a Roundabout Enter step.</p>
    pub fn roundabout_enter_step_details(&self) -> ::std::option::Option<&crate::types::RouteRoundaboutEnterStepDetails> {
        self.roundabout_enter_step_details.as_ref()
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn roundabout_exit_step_details(&self) -> ::std::option::Option<&crate::types::RouteRoundaboutExitStepDetails> {
        self.roundabout_exit_step_details.as_ref()
    }
    /// <p>Details that are specific to a Roundabout Pass step.</p>
    pub fn roundabout_pass_step_details(&self) -> ::std::option::Option<&crate::types::RouteRoundaboutPassStepDetails> {
        self.roundabout_pass_step_details.as_ref()
    }
    /// <p>Sign post information of the action, applicable only for TurnByTurn steps. See RouteSignpost for details of sub-attributes.</p>
    pub fn signpost(&self) -> ::std::option::Option<&crate::types::RouteSignpost> {
        self.signpost.as_ref()
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn turn_step_details(&self) -> ::std::option::Option<&crate::types::RouteTurnStepDetails> {
        self.turn_step_details.as_ref()
    }
    /// <p>Type of the step.</p>
    pub fn r#type(&self) -> &crate::types::RouteVehicleTravelStepType {
        &self.r#type
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn u_turn_step_details(&self) -> ::std::option::Option<&crate::types::RouteUTurnStepDetails> {
        self.u_turn_step_details.as_ref()
    }
}
impl RouteVehicleTravelStep {
    /// Creates a new builder-style object to manufacture [`RouteVehicleTravelStep`](crate::types::RouteVehicleTravelStep).
    pub fn builder() -> crate::types::builders::RouteVehicleTravelStepBuilder {
        crate::types::builders::RouteVehicleTravelStepBuilder::default()
    }
}

/// A builder for [`RouteVehicleTravelStep`](crate::types::RouteVehicleTravelStep).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteVehicleTravelStepBuilder {
    pub(crate) continue_highway_step_details: ::std::option::Option<crate::types::RouteContinueHighwayStepDetails>,
    pub(crate) continue_step_details: ::std::option::Option<crate::types::RouteContinueStepDetails>,
    pub(crate) current_road: ::std::option::Option<crate::types::RouteRoad>,
    pub(crate) distance: ::std::option::Option<i64>,
    pub(crate) duration: ::std::option::Option<i64>,
    pub(crate) enter_highway_step_details: ::std::option::Option<crate::types::RouteEnterHighwayStepDetails>,
    pub(crate) exit_number: ::std::option::Option<::std::vec::Vec<crate::types::LocalizedString>>,
    pub(crate) exit_step_details: ::std::option::Option<crate::types::RouteExitStepDetails>,
    pub(crate) geometry_offset: ::std::option::Option<i32>,
    pub(crate) instruction: ::std::option::Option<::std::string::String>,
    pub(crate) keep_step_details: ::std::option::Option<crate::types::RouteKeepStepDetails>,
    pub(crate) next_road: ::std::option::Option<crate::types::RouteRoad>,
    pub(crate) ramp_step_details: ::std::option::Option<crate::types::RouteRampStepDetails>,
    pub(crate) roundabout_enter_step_details: ::std::option::Option<crate::types::RouteRoundaboutEnterStepDetails>,
    pub(crate) roundabout_exit_step_details: ::std::option::Option<crate::types::RouteRoundaboutExitStepDetails>,
    pub(crate) roundabout_pass_step_details: ::std::option::Option<crate::types::RouteRoundaboutPassStepDetails>,
    pub(crate) signpost: ::std::option::Option<crate::types::RouteSignpost>,
    pub(crate) turn_step_details: ::std::option::Option<crate::types::RouteTurnStepDetails>,
    pub(crate) r#type: ::std::option::Option<crate::types::RouteVehicleTravelStepType>,
    pub(crate) u_turn_step_details: ::std::option::Option<crate::types::RouteUTurnStepDetails>,
}
impl RouteVehicleTravelStepBuilder {
    /// <p>Details that are specific to a Continue Highway step.</p>
    pub fn continue_highway_step_details(mut self, input: crate::types::RouteContinueHighwayStepDetails) -> Self {
        self.continue_highway_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Continue Highway step.</p>
    pub fn set_continue_highway_step_details(mut self, input: ::std::option::Option<crate::types::RouteContinueHighwayStepDetails>) -> Self {
        self.continue_highway_step_details = input;
        self
    }
    /// <p>Details that are specific to a Continue Highway step.</p>
    pub fn get_continue_highway_step_details(&self) -> &::std::option::Option<crate::types::RouteContinueHighwayStepDetails> {
        &self.continue_highway_step_details
    }
    /// <p>Details that are specific to a Continue step.</p>
    pub fn continue_step_details(mut self, input: crate::types::RouteContinueStepDetails) -> Self {
        self.continue_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Continue step.</p>
    pub fn set_continue_step_details(mut self, input: ::std::option::Option<crate::types::RouteContinueStepDetails>) -> Self {
        self.continue_step_details = input;
        self
    }
    /// <p>Details that are specific to a Continue step.</p>
    pub fn get_continue_step_details(&self) -> &::std::option::Option<crate::types::RouteContinueStepDetails> {
        &self.continue_step_details
    }
    /// <p>Details of the current road.</p>
    pub fn current_road(mut self, input: crate::types::RouteRoad) -> Self {
        self.current_road = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details of the current road.</p>
    pub fn set_current_road(mut self, input: ::std::option::Option<crate::types::RouteRoad>) -> Self {
        self.current_road = input;
        self
    }
    /// <p>Details of the current road.</p>
    pub fn get_current_road(&self) -> &::std::option::Option<crate::types::RouteRoad> {
        &self.current_road
    }
    /// <p>Distance of the step.</p>
    pub fn distance(mut self, input: i64) -> Self {
        self.distance = ::std::option::Option::Some(input);
        self
    }
    /// <p>Distance of the step.</p>
    pub fn set_distance(mut self, input: ::std::option::Option<i64>) -> Self {
        self.distance = input;
        self
    }
    /// <p>Distance of the step.</p>
    pub fn get_distance(&self) -> &::std::option::Option<i64> {
        &self.distance
    }
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    /// This field is required.
    pub fn duration(mut self, input: i64) -> Self {
        self.duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn set_duration(mut self, input: ::std::option::Option<i64>) -> Self {
        self.duration = input;
        self
    }
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn get_duration(&self) -> &::std::option::Option<i64> {
        &self.duration
    }
    /// <p>Details that are specific to a Enter Highway step.</p>
    pub fn enter_highway_step_details(mut self, input: crate::types::RouteEnterHighwayStepDetails) -> Self {
        self.enter_highway_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Enter Highway step.</p>
    pub fn set_enter_highway_step_details(mut self, input: ::std::option::Option<crate::types::RouteEnterHighwayStepDetails>) -> Self {
        self.enter_highway_step_details = input;
        self
    }
    /// <p>Details that are specific to a Enter Highway step.</p>
    pub fn get_enter_highway_step_details(&self) -> &::std::option::Option<crate::types::RouteEnterHighwayStepDetails> {
        &self.enter_highway_step_details
    }
    /// Appends an item to `exit_number`.
    ///
    /// To override the contents of this collection use [`set_exit_number`](Self::set_exit_number).
    ///
    /// <p>Exit number of the road exit, if applicable.</p>
    pub fn exit_number(mut self, input: crate::types::LocalizedString) -> Self {
        let mut v = self.exit_number.unwrap_or_default();
        v.push(input);
        self.exit_number = ::std::option::Option::Some(v);
        self
    }
    /// <p>Exit number of the road exit, if applicable.</p>
    pub fn set_exit_number(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LocalizedString>>) -> Self {
        self.exit_number = input;
        self
    }
    /// <p>Exit number of the road exit, if applicable.</p>
    pub fn get_exit_number(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LocalizedString>> {
        &self.exit_number
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn exit_step_details(mut self, input: crate::types::RouteExitStepDetails) -> Self {
        self.exit_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn set_exit_step_details(mut self, input: ::std::option::Option<crate::types::RouteExitStepDetails>) -> Self {
        self.exit_step_details = input;
        self
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn get_exit_step_details(&self) -> &::std::option::Option<crate::types::RouteExitStepDetails> {
        &self.exit_step_details
    }
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn geometry_offset(mut self, input: i32) -> Self {
        self.geometry_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn set_geometry_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.geometry_offset = input;
        self
    }
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn get_geometry_offset(&self) -> &::std::option::Option<i32> {
        &self.geometry_offset
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn instruction(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instruction = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn set_instruction(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instruction = input;
        self
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn get_instruction(&self) -> &::std::option::Option<::std::string::String> {
        &self.instruction
    }
    /// <p>Details that are specific to a Keep step.</p>
    pub fn keep_step_details(mut self, input: crate::types::RouteKeepStepDetails) -> Self {
        self.keep_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Keep step.</p>
    pub fn set_keep_step_details(mut self, input: ::std::option::Option<crate::types::RouteKeepStepDetails>) -> Self {
        self.keep_step_details = input;
        self
    }
    /// <p>Details that are specific to a Keep step.</p>
    pub fn get_keep_step_details(&self) -> &::std::option::Option<crate::types::RouteKeepStepDetails> {
        &self.keep_step_details
    }
    /// <p>Details of the next road. See RouteRoad for details of sub-attributes.</p>
    pub fn next_road(mut self, input: crate::types::RouteRoad) -> Self {
        self.next_road = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details of the next road. See RouteRoad for details of sub-attributes.</p>
    pub fn set_next_road(mut self, input: ::std::option::Option<crate::types::RouteRoad>) -> Self {
        self.next_road = input;
        self
    }
    /// <p>Details of the next road. See RouteRoad for details of sub-attributes.</p>
    pub fn get_next_road(&self) -> &::std::option::Option<crate::types::RouteRoad> {
        &self.next_road
    }
    /// <p>Details that are specific to a Ramp step.</p>
    pub fn ramp_step_details(mut self, input: crate::types::RouteRampStepDetails) -> Self {
        self.ramp_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Ramp step.</p>
    pub fn set_ramp_step_details(mut self, input: ::std::option::Option<crate::types::RouteRampStepDetails>) -> Self {
        self.ramp_step_details = input;
        self
    }
    /// <p>Details that are specific to a Ramp step.</p>
    pub fn get_ramp_step_details(&self) -> &::std::option::Option<crate::types::RouteRampStepDetails> {
        &self.ramp_step_details
    }
    /// <p>Details that are specific to a Roundabout Enter step.</p>
    pub fn roundabout_enter_step_details(mut self, input: crate::types::RouteRoundaboutEnterStepDetails) -> Self {
        self.roundabout_enter_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Roundabout Enter step.</p>
    pub fn set_roundabout_enter_step_details(mut self, input: ::std::option::Option<crate::types::RouteRoundaboutEnterStepDetails>) -> Self {
        self.roundabout_enter_step_details = input;
        self
    }
    /// <p>Details that are specific to a Roundabout Enter step.</p>
    pub fn get_roundabout_enter_step_details(&self) -> &::std::option::Option<crate::types::RouteRoundaboutEnterStepDetails> {
        &self.roundabout_enter_step_details
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn roundabout_exit_step_details(mut self, input: crate::types::RouteRoundaboutExitStepDetails) -> Self {
        self.roundabout_exit_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn set_roundabout_exit_step_details(mut self, input: ::std::option::Option<crate::types::RouteRoundaboutExitStepDetails>) -> Self {
        self.roundabout_exit_step_details = input;
        self
    }
    /// <p>Details that are specific to a Roundabout Exit step.</p>
    pub fn get_roundabout_exit_step_details(&self) -> &::std::option::Option<crate::types::RouteRoundaboutExitStepDetails> {
        &self.roundabout_exit_step_details
    }
    /// <p>Details that are specific to a Roundabout Pass step.</p>
    pub fn roundabout_pass_step_details(mut self, input: crate::types::RouteRoundaboutPassStepDetails) -> Self {
        self.roundabout_pass_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Roundabout Pass step.</p>
    pub fn set_roundabout_pass_step_details(mut self, input: ::std::option::Option<crate::types::RouteRoundaboutPassStepDetails>) -> Self {
        self.roundabout_pass_step_details = input;
        self
    }
    /// <p>Details that are specific to a Roundabout Pass step.</p>
    pub fn get_roundabout_pass_step_details(&self) -> &::std::option::Option<crate::types::RouteRoundaboutPassStepDetails> {
        &self.roundabout_pass_step_details
    }
    /// <p>Sign post information of the action, applicable only for TurnByTurn steps. See RouteSignpost for details of sub-attributes.</p>
    pub fn signpost(mut self, input: crate::types::RouteSignpost) -> Self {
        self.signpost = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sign post information of the action, applicable only for TurnByTurn steps. See RouteSignpost for details of sub-attributes.</p>
    pub fn set_signpost(mut self, input: ::std::option::Option<crate::types::RouteSignpost>) -> Self {
        self.signpost = input;
        self
    }
    /// <p>Sign post information of the action, applicable only for TurnByTurn steps. See RouteSignpost for details of sub-attributes.</p>
    pub fn get_signpost(&self) -> &::std::option::Option<crate::types::RouteSignpost> {
        &self.signpost
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn turn_step_details(mut self, input: crate::types::RouteTurnStepDetails) -> Self {
        self.turn_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn set_turn_step_details(mut self, input: ::std::option::Option<crate::types::RouteTurnStepDetails>) -> Self {
        self.turn_step_details = input;
        self
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn get_turn_step_details(&self) -> &::std::option::Option<crate::types::RouteTurnStepDetails> {
        &self.turn_step_details
    }
    /// <p>Type of the step.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::RouteVehicleTravelStepType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of the step.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RouteVehicleTravelStepType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of the step.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RouteVehicleTravelStepType> {
        &self.r#type
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn u_turn_step_details(mut self, input: crate::types::RouteUTurnStepDetails) -> Self {
        self.u_turn_step_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn set_u_turn_step_details(mut self, input: ::std::option::Option<crate::types::RouteUTurnStepDetails>) -> Self {
        self.u_turn_step_details = input;
        self
    }
    /// <p>Details that are specific to a Turn step.</p>
    pub fn get_u_turn_step_details(&self) -> &::std::option::Option<crate::types::RouteUTurnStepDetails> {
        &self.u_turn_step_details
    }
    /// Consumes the builder and constructs a [`RouteVehicleTravelStep`](crate::types::RouteVehicleTravelStep).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::RouteVehicleTravelStepBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::RouteVehicleTravelStep, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RouteVehicleTravelStep {
            continue_highway_step_details: self.continue_highway_step_details,
            continue_step_details: self.continue_step_details,
            current_road: self.current_road,
            distance: self.distance.unwrap_or_default(),
            duration: self.duration.unwrap_or_default(),
            enter_highway_step_details: self.enter_highway_step_details,
            exit_number: self.exit_number,
            exit_step_details: self.exit_step_details,
            geometry_offset: self.geometry_offset,
            instruction: self.instruction,
            keep_step_details: self.keep_step_details,
            next_road: self.next_road,
            ramp_step_details: self.ramp_step_details,
            roundabout_enter_step_details: self.roundabout_enter_step_details,
            roundabout_exit_step_details: self.roundabout_exit_step_details,
            roundabout_pass_step_details: self.roundabout_pass_step_details,
            signpost: self.signpost,
            turn_step_details: self.turn_step_details,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building RouteVehicleTravelStep",
                )
            })?,
            u_turn_step_details: self.u_turn_step_details,
        })
    }
}
