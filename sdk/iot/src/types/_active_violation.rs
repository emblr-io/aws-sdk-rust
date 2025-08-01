// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an active Device Defender security profile behavior violation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActiveViolation {
    /// <p>The ID of the active violation.</p>
    pub violation_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the thing responsible for the active violation.</p>
    pub thing_name: ::std::option::Option<::std::string::String>,
    /// <p>The security profile with the behavior is in violation.</p>
    pub security_profile_name: ::std::option::Option<::std::string::String>,
    /// <p>The behavior that is being violated.</p>
    pub behavior: ::std::option::Option<crate::types::Behavior>,
    /// <p>The value of the metric (the measurement) that caused the most recent violation.</p>
    pub last_violation_value: ::std::option::Option<crate::types::MetricValue>,
    /// <p>The details of a violation event.</p>
    pub violation_event_additional_info: ::std::option::Option<crate::types::ViolationEventAdditionalInfo>,
    /// <p>The verification state of the violation (detect alarm).</p>
    pub verification_state: ::std::option::Option<crate::types::VerificationState>,
    /// <p>The description of the verification state of the violation.</p>
    pub verification_state_description: ::std::option::Option<::std::string::String>,
    /// <p>The time the most recent violation occurred.</p>
    pub last_violation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time the violation started.</p>
    pub violation_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ActiveViolation {
    /// <p>The ID of the active violation.</p>
    pub fn violation_id(&self) -> ::std::option::Option<&str> {
        self.violation_id.as_deref()
    }
    /// <p>The name of the thing responsible for the active violation.</p>
    pub fn thing_name(&self) -> ::std::option::Option<&str> {
        self.thing_name.as_deref()
    }
    /// <p>The security profile with the behavior is in violation.</p>
    pub fn security_profile_name(&self) -> ::std::option::Option<&str> {
        self.security_profile_name.as_deref()
    }
    /// <p>The behavior that is being violated.</p>
    pub fn behavior(&self) -> ::std::option::Option<&crate::types::Behavior> {
        self.behavior.as_ref()
    }
    /// <p>The value of the metric (the measurement) that caused the most recent violation.</p>
    pub fn last_violation_value(&self) -> ::std::option::Option<&crate::types::MetricValue> {
        self.last_violation_value.as_ref()
    }
    /// <p>The details of a violation event.</p>
    pub fn violation_event_additional_info(&self) -> ::std::option::Option<&crate::types::ViolationEventAdditionalInfo> {
        self.violation_event_additional_info.as_ref()
    }
    /// <p>The verification state of the violation (detect alarm).</p>
    pub fn verification_state(&self) -> ::std::option::Option<&crate::types::VerificationState> {
        self.verification_state.as_ref()
    }
    /// <p>The description of the verification state of the violation.</p>
    pub fn verification_state_description(&self) -> ::std::option::Option<&str> {
        self.verification_state_description.as_deref()
    }
    /// <p>The time the most recent violation occurred.</p>
    pub fn last_violation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_violation_time.as_ref()
    }
    /// <p>The time the violation started.</p>
    pub fn violation_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.violation_start_time.as_ref()
    }
}
impl ActiveViolation {
    /// Creates a new builder-style object to manufacture [`ActiveViolation`](crate::types::ActiveViolation).
    pub fn builder() -> crate::types::builders::ActiveViolationBuilder {
        crate::types::builders::ActiveViolationBuilder::default()
    }
}

/// A builder for [`ActiveViolation`](crate::types::ActiveViolation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActiveViolationBuilder {
    pub(crate) violation_id: ::std::option::Option<::std::string::String>,
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) security_profile_name: ::std::option::Option<::std::string::String>,
    pub(crate) behavior: ::std::option::Option<crate::types::Behavior>,
    pub(crate) last_violation_value: ::std::option::Option<crate::types::MetricValue>,
    pub(crate) violation_event_additional_info: ::std::option::Option<crate::types::ViolationEventAdditionalInfo>,
    pub(crate) verification_state: ::std::option::Option<crate::types::VerificationState>,
    pub(crate) verification_state_description: ::std::option::Option<::std::string::String>,
    pub(crate) last_violation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) violation_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ActiveViolationBuilder {
    /// <p>The ID of the active violation.</p>
    pub fn violation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.violation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the active violation.</p>
    pub fn set_violation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.violation_id = input;
        self
    }
    /// <p>The ID of the active violation.</p>
    pub fn get_violation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.violation_id
    }
    /// <p>The name of the thing responsible for the active violation.</p>
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the thing responsible for the active violation.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the thing responsible for the active violation.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// <p>The security profile with the behavior is in violation.</p>
    pub fn security_profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The security profile with the behavior is in violation.</p>
    pub fn set_security_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_profile_name = input;
        self
    }
    /// <p>The security profile with the behavior is in violation.</p>
    pub fn get_security_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_profile_name
    }
    /// <p>The behavior that is being violated.</p>
    pub fn behavior(mut self, input: crate::types::Behavior) -> Self {
        self.behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>The behavior that is being violated.</p>
    pub fn set_behavior(mut self, input: ::std::option::Option<crate::types::Behavior>) -> Self {
        self.behavior = input;
        self
    }
    /// <p>The behavior that is being violated.</p>
    pub fn get_behavior(&self) -> &::std::option::Option<crate::types::Behavior> {
        &self.behavior
    }
    /// <p>The value of the metric (the measurement) that caused the most recent violation.</p>
    pub fn last_violation_value(mut self, input: crate::types::MetricValue) -> Self {
        self.last_violation_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the metric (the measurement) that caused the most recent violation.</p>
    pub fn set_last_violation_value(mut self, input: ::std::option::Option<crate::types::MetricValue>) -> Self {
        self.last_violation_value = input;
        self
    }
    /// <p>The value of the metric (the measurement) that caused the most recent violation.</p>
    pub fn get_last_violation_value(&self) -> &::std::option::Option<crate::types::MetricValue> {
        &self.last_violation_value
    }
    /// <p>The details of a violation event.</p>
    pub fn violation_event_additional_info(mut self, input: crate::types::ViolationEventAdditionalInfo) -> Self {
        self.violation_event_additional_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of a violation event.</p>
    pub fn set_violation_event_additional_info(mut self, input: ::std::option::Option<crate::types::ViolationEventAdditionalInfo>) -> Self {
        self.violation_event_additional_info = input;
        self
    }
    /// <p>The details of a violation event.</p>
    pub fn get_violation_event_additional_info(&self) -> &::std::option::Option<crate::types::ViolationEventAdditionalInfo> {
        &self.violation_event_additional_info
    }
    /// <p>The verification state of the violation (detect alarm).</p>
    pub fn verification_state(mut self, input: crate::types::VerificationState) -> Self {
        self.verification_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The verification state of the violation (detect alarm).</p>
    pub fn set_verification_state(mut self, input: ::std::option::Option<crate::types::VerificationState>) -> Self {
        self.verification_state = input;
        self
    }
    /// <p>The verification state of the violation (detect alarm).</p>
    pub fn get_verification_state(&self) -> &::std::option::Option<crate::types::VerificationState> {
        &self.verification_state
    }
    /// <p>The description of the verification state of the violation.</p>
    pub fn verification_state_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verification_state_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the verification state of the violation.</p>
    pub fn set_verification_state_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verification_state_description = input;
        self
    }
    /// <p>The description of the verification state of the violation.</p>
    pub fn get_verification_state_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.verification_state_description
    }
    /// <p>The time the most recent violation occurred.</p>
    pub fn last_violation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_violation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the most recent violation occurred.</p>
    pub fn set_last_violation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_violation_time = input;
        self
    }
    /// <p>The time the most recent violation occurred.</p>
    pub fn get_last_violation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_violation_time
    }
    /// <p>The time the violation started.</p>
    pub fn violation_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.violation_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the violation started.</p>
    pub fn set_violation_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.violation_start_time = input;
        self
    }
    /// <p>The time the violation started.</p>
    pub fn get_violation_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.violation_start_time
    }
    /// Consumes the builder and constructs a [`ActiveViolation`](crate::types::ActiveViolation).
    pub fn build(self) -> crate::types::ActiveViolation {
        crate::types::ActiveViolation {
            violation_id: self.violation_id,
            thing_name: self.thing_name,
            security_profile_name: self.security_profile_name,
            behavior: self.behavior,
            last_violation_value: self.last_violation_value,
            violation_event_additional_info: self.violation_event_additional_info,
            verification_state: self.verification_state,
            verification_state_description: self.verification_state_description,
            last_violation_time: self.last_violation_time,
            violation_start_time: self.violation_start_time,
        }
    }
}
