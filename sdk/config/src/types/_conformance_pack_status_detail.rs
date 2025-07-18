// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Status details of a conformance pack.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConformancePackStatusDetail {
    /// <p>Name of the conformance pack.</p>
    pub conformance_pack_name: ::std::string::String,
    /// <p>ID of the conformance pack.</p>
    pub conformance_pack_id: ::std::string::String,
    /// <p>Amazon Resource Name (ARN) of comformance pack.</p>
    pub conformance_pack_arn: ::std::string::String,
    /// <p>Indicates deployment status of conformance pack.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE_IN_PROGRESS when a conformance pack creation is in progress for an account.</p></li>
    /// <li>
    /// <p>CREATE_COMPLETE when a conformance pack has been successfully created in your account.</p></li>
    /// <li>
    /// <p>CREATE_FAILED when a conformance pack creation failed in your account.</p></li>
    /// <li>
    /// <p>DELETE_IN_PROGRESS when a conformance pack deletion is in progress.</p></li>
    /// <li>
    /// <p>DELETE_FAILED when a conformance pack deletion failed in your account.</p></li>
    /// </ul>
    pub conformance_pack_state: crate::types::ConformancePackState,
    /// <p>Amazon Resource Name (ARN) of CloudFormation stack.</p>
    pub stack_arn: ::std::string::String,
    /// <p>The reason of conformance pack creation failure.</p>
    pub conformance_pack_status_reason: ::std::option::Option<::std::string::String>,
    /// <p>Last time when conformation pack creation and update was requested.</p>
    pub last_update_requested_time: ::aws_smithy_types::DateTime,
    /// <p>Last time when conformation pack creation and update was successful.</p>
    pub last_update_completed_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConformancePackStatusDetail {
    /// <p>Name of the conformance pack.</p>
    pub fn conformance_pack_name(&self) -> &str {
        use std::ops::Deref;
        self.conformance_pack_name.deref()
    }
    /// <p>ID of the conformance pack.</p>
    pub fn conformance_pack_id(&self) -> &str {
        use std::ops::Deref;
        self.conformance_pack_id.deref()
    }
    /// <p>Amazon Resource Name (ARN) of comformance pack.</p>
    pub fn conformance_pack_arn(&self) -> &str {
        use std::ops::Deref;
        self.conformance_pack_arn.deref()
    }
    /// <p>Indicates deployment status of conformance pack.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE_IN_PROGRESS when a conformance pack creation is in progress for an account.</p></li>
    /// <li>
    /// <p>CREATE_COMPLETE when a conformance pack has been successfully created in your account.</p></li>
    /// <li>
    /// <p>CREATE_FAILED when a conformance pack creation failed in your account.</p></li>
    /// <li>
    /// <p>DELETE_IN_PROGRESS when a conformance pack deletion is in progress.</p></li>
    /// <li>
    /// <p>DELETE_FAILED when a conformance pack deletion failed in your account.</p></li>
    /// </ul>
    pub fn conformance_pack_state(&self) -> &crate::types::ConformancePackState {
        &self.conformance_pack_state
    }
    /// <p>Amazon Resource Name (ARN) of CloudFormation stack.</p>
    pub fn stack_arn(&self) -> &str {
        use std::ops::Deref;
        self.stack_arn.deref()
    }
    /// <p>The reason of conformance pack creation failure.</p>
    pub fn conformance_pack_status_reason(&self) -> ::std::option::Option<&str> {
        self.conformance_pack_status_reason.as_deref()
    }
    /// <p>Last time when conformation pack creation and update was requested.</p>
    pub fn last_update_requested_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_update_requested_time
    }
    /// <p>Last time when conformation pack creation and update was successful.</p>
    pub fn last_update_completed_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_update_completed_time.as_ref()
    }
}
impl ConformancePackStatusDetail {
    /// Creates a new builder-style object to manufacture [`ConformancePackStatusDetail`](crate::types::ConformancePackStatusDetail).
    pub fn builder() -> crate::types::builders::ConformancePackStatusDetailBuilder {
        crate::types::builders::ConformancePackStatusDetailBuilder::default()
    }
}

/// A builder for [`ConformancePackStatusDetail`](crate::types::ConformancePackStatusDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConformancePackStatusDetailBuilder {
    pub(crate) conformance_pack_name: ::std::option::Option<::std::string::String>,
    pub(crate) conformance_pack_id: ::std::option::Option<::std::string::String>,
    pub(crate) conformance_pack_arn: ::std::option::Option<::std::string::String>,
    pub(crate) conformance_pack_state: ::std::option::Option<crate::types::ConformancePackState>,
    pub(crate) stack_arn: ::std::option::Option<::std::string::String>,
    pub(crate) conformance_pack_status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) last_update_requested_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_update_completed_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConformancePackStatusDetailBuilder {
    /// <p>Name of the conformance pack.</p>
    /// This field is required.
    pub fn conformance_pack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conformance_pack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the conformance pack.</p>
    pub fn set_conformance_pack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conformance_pack_name = input;
        self
    }
    /// <p>Name of the conformance pack.</p>
    pub fn get_conformance_pack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.conformance_pack_name
    }
    /// <p>ID of the conformance pack.</p>
    /// This field is required.
    pub fn conformance_pack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conformance_pack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of the conformance pack.</p>
    pub fn set_conformance_pack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conformance_pack_id = input;
        self
    }
    /// <p>ID of the conformance pack.</p>
    pub fn get_conformance_pack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.conformance_pack_id
    }
    /// <p>Amazon Resource Name (ARN) of comformance pack.</p>
    /// This field is required.
    pub fn conformance_pack_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conformance_pack_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of comformance pack.</p>
    pub fn set_conformance_pack_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conformance_pack_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of comformance pack.</p>
    pub fn get_conformance_pack_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.conformance_pack_arn
    }
    /// <p>Indicates deployment status of conformance pack.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE_IN_PROGRESS when a conformance pack creation is in progress for an account.</p></li>
    /// <li>
    /// <p>CREATE_COMPLETE when a conformance pack has been successfully created in your account.</p></li>
    /// <li>
    /// <p>CREATE_FAILED when a conformance pack creation failed in your account.</p></li>
    /// <li>
    /// <p>DELETE_IN_PROGRESS when a conformance pack deletion is in progress.</p></li>
    /// <li>
    /// <p>DELETE_FAILED when a conformance pack deletion failed in your account.</p></li>
    /// </ul>
    /// This field is required.
    pub fn conformance_pack_state(mut self, input: crate::types::ConformancePackState) -> Self {
        self.conformance_pack_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates deployment status of conformance pack.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE_IN_PROGRESS when a conformance pack creation is in progress for an account.</p></li>
    /// <li>
    /// <p>CREATE_COMPLETE when a conformance pack has been successfully created in your account.</p></li>
    /// <li>
    /// <p>CREATE_FAILED when a conformance pack creation failed in your account.</p></li>
    /// <li>
    /// <p>DELETE_IN_PROGRESS when a conformance pack deletion is in progress.</p></li>
    /// <li>
    /// <p>DELETE_FAILED when a conformance pack deletion failed in your account.</p></li>
    /// </ul>
    pub fn set_conformance_pack_state(mut self, input: ::std::option::Option<crate::types::ConformancePackState>) -> Self {
        self.conformance_pack_state = input;
        self
    }
    /// <p>Indicates deployment status of conformance pack.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE_IN_PROGRESS when a conformance pack creation is in progress for an account.</p></li>
    /// <li>
    /// <p>CREATE_COMPLETE when a conformance pack has been successfully created in your account.</p></li>
    /// <li>
    /// <p>CREATE_FAILED when a conformance pack creation failed in your account.</p></li>
    /// <li>
    /// <p>DELETE_IN_PROGRESS when a conformance pack deletion is in progress.</p></li>
    /// <li>
    /// <p>DELETE_FAILED when a conformance pack deletion failed in your account.</p></li>
    /// </ul>
    pub fn get_conformance_pack_state(&self) -> &::std::option::Option<crate::types::ConformancePackState> {
        &self.conformance_pack_state
    }
    /// <p>Amazon Resource Name (ARN) of CloudFormation stack.</p>
    /// This field is required.
    pub fn stack_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of CloudFormation stack.</p>
    pub fn set_stack_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of CloudFormation stack.</p>
    pub fn get_stack_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_arn
    }
    /// <p>The reason of conformance pack creation failure.</p>
    pub fn conformance_pack_status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conformance_pack_status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason of conformance pack creation failure.</p>
    pub fn set_conformance_pack_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conformance_pack_status_reason = input;
        self
    }
    /// <p>The reason of conformance pack creation failure.</p>
    pub fn get_conformance_pack_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.conformance_pack_status_reason
    }
    /// <p>Last time when conformation pack creation and update was requested.</p>
    /// This field is required.
    pub fn last_update_requested_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_requested_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Last time when conformation pack creation and update was requested.</p>
    pub fn set_last_update_requested_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_requested_time = input;
        self
    }
    /// <p>Last time when conformation pack creation and update was requested.</p>
    pub fn get_last_update_requested_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_requested_time
    }
    /// <p>Last time when conformation pack creation and update was successful.</p>
    pub fn last_update_completed_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_completed_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Last time when conformation pack creation and update was successful.</p>
    pub fn set_last_update_completed_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_completed_time = input;
        self
    }
    /// <p>Last time when conformation pack creation and update was successful.</p>
    pub fn get_last_update_completed_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_completed_time
    }
    /// Consumes the builder and constructs a [`ConformancePackStatusDetail`](crate::types::ConformancePackStatusDetail).
    /// This method will fail if any of the following fields are not set:
    /// - [`conformance_pack_name`](crate::types::builders::ConformancePackStatusDetailBuilder::conformance_pack_name)
    /// - [`conformance_pack_id`](crate::types::builders::ConformancePackStatusDetailBuilder::conformance_pack_id)
    /// - [`conformance_pack_arn`](crate::types::builders::ConformancePackStatusDetailBuilder::conformance_pack_arn)
    /// - [`conformance_pack_state`](crate::types::builders::ConformancePackStatusDetailBuilder::conformance_pack_state)
    /// - [`stack_arn`](crate::types::builders::ConformancePackStatusDetailBuilder::stack_arn)
    /// - [`last_update_requested_time`](crate::types::builders::ConformancePackStatusDetailBuilder::last_update_requested_time)
    pub fn build(self) -> ::std::result::Result<crate::types::ConformancePackStatusDetail, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConformancePackStatusDetail {
            conformance_pack_name: self.conformance_pack_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conformance_pack_name",
                    "conformance_pack_name was not specified but it is required when building ConformancePackStatusDetail",
                )
            })?,
            conformance_pack_id: self.conformance_pack_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conformance_pack_id",
                    "conformance_pack_id was not specified but it is required when building ConformancePackStatusDetail",
                )
            })?,
            conformance_pack_arn: self.conformance_pack_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conformance_pack_arn",
                    "conformance_pack_arn was not specified but it is required when building ConformancePackStatusDetail",
                )
            })?,
            conformance_pack_state: self.conformance_pack_state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conformance_pack_state",
                    "conformance_pack_state was not specified but it is required when building ConformancePackStatusDetail",
                )
            })?,
            stack_arn: self.stack_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stack_arn",
                    "stack_arn was not specified but it is required when building ConformancePackStatusDetail",
                )
            })?,
            conformance_pack_status_reason: self.conformance_pack_status_reason,
            last_update_requested_time: self.last_update_requested_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_update_requested_time",
                    "last_update_requested_time was not specified but it is required when building ConformancePackStatusDetail",
                )
            })?,
            last_update_completed_time: self.last_update_completed_time,
        })
    }
}
