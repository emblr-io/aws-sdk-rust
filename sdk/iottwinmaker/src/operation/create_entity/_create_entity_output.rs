// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEntityOutput {
    /// <p>The ID of the entity.</p>
    pub entity_id: ::std::string::String,
    /// <p>The ARN of the entity.</p>
    pub arn: ::std::string::String,
    /// <p>The date and time when the entity was created.</p>
    pub creation_date_time: ::aws_smithy_types::DateTime,
    /// <p>The current state of the entity.</p>
    pub state: crate::types::State,
    _request_id: Option<String>,
}
impl CreateEntityOutput {
    /// <p>The ID of the entity.</p>
    pub fn entity_id(&self) -> &str {
        use std::ops::Deref;
        self.entity_id.deref()
    }
    /// <p>The ARN of the entity.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The date and time when the entity was created.</p>
    pub fn creation_date_time(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_date_time
    }
    /// <p>The current state of the entity.</p>
    pub fn state(&self) -> &crate::types::State {
        &self.state
    }
}
impl ::aws_types::request_id::RequestId for CreateEntityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEntityOutput {
    /// Creates a new builder-style object to manufacture [`CreateEntityOutput`](crate::operation::create_entity::CreateEntityOutput).
    pub fn builder() -> crate::operation::create_entity::builders::CreateEntityOutputBuilder {
        crate::operation::create_entity::builders::CreateEntityOutputBuilder::default()
    }
}

/// A builder for [`CreateEntityOutput`](crate::operation::create_entity::CreateEntityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEntityOutputBuilder {
    pub(crate) entity_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::State>,
    _request_id: Option<String>,
}
impl CreateEntityOutputBuilder {
    /// <p>The ID of the entity.</p>
    /// This field is required.
    pub fn entity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the entity.</p>
    pub fn set_entity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id = input;
        self
    }
    /// <p>The ID of the entity.</p>
    pub fn get_entity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id
    }
    /// <p>The ARN of the entity.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the entity.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the entity.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The date and time when the entity was created.</p>
    /// This field is required.
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the entity was created.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The date and time when the entity was created.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The current state of the entity.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::State) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the entity.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::State>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of the entity.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::State> {
        &self.state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEntityOutput`](crate::operation::create_entity::CreateEntityOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`entity_id`](crate::operation::create_entity::builders::CreateEntityOutputBuilder::entity_id)
    /// - [`arn`](crate::operation::create_entity::builders::CreateEntityOutputBuilder::arn)
    /// - [`creation_date_time`](crate::operation::create_entity::builders::CreateEntityOutputBuilder::creation_date_time)
    /// - [`state`](crate::operation::create_entity::builders::CreateEntityOutputBuilder::state)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_entity::CreateEntityOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_entity::CreateEntityOutput {
            entity_id: self.entity_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entity_id",
                    "entity_id was not specified but it is required when building CreateEntityOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building CreateEntityOutput",
                )
            })?,
            creation_date_time: self.creation_date_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_date_time",
                    "creation_date_time was not specified but it is required when building CreateEntityOutput",
                )
            })?,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building CreateEntityOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
