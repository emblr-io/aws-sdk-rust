// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDevEnvironmentOutput {
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub id: ::std::string::String,
    /// <p>The name of the space.</p>
    pub space_name: ::std::string::String,
    /// <p>The name of the project in the space.</p>
    pub project_name: ::std::string::String,
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub alias: ::std::option::Option<::std::string::String>,
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub ides: ::std::option::Option<::std::vec::Vec<crate::types::IdeConfiguration>>,
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub instance_type: ::std::option::Option<crate::types::InstanceType>,
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub inactivity_timeout_minutes: i32,
    /// <p>A user-specified idempotency token. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, the subsequent retries return the result from the original successful request and have no additional effect.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateDevEnvironmentOutput {
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> &str {
        use std::ops::Deref;
        self.space_name.deref()
    }
    /// <p>The name of the project in the space.</p>
    pub fn project_name(&self) -> &str {
        use std::ops::Deref;
        self.project_name.deref()
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ides.is_none()`.
    pub fn ides(&self) -> &[crate::types::IdeConfiguration] {
        self.ides.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&crate::types::InstanceType> {
        self.instance_type.as_ref()
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn inactivity_timeout_minutes(&self) -> i32 {
        self.inactivity_timeout_minutes
    }
    /// <p>A user-specified idempotency token. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, the subsequent retries return the result from the original successful request and have no additional effect.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDevEnvironmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDevEnvironmentOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDevEnvironmentOutput`](crate::operation::update_dev_environment::UpdateDevEnvironmentOutput).
    pub fn builder() -> crate::operation::update_dev_environment::builders::UpdateDevEnvironmentOutputBuilder {
        crate::operation::update_dev_environment::builders::UpdateDevEnvironmentOutputBuilder::default()
    }
}

/// A builder for [`UpdateDevEnvironmentOutput`](crate::operation::update_dev_environment::UpdateDevEnvironmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDevEnvironmentOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) project_name: ::std::option::Option<::std::string::String>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
    pub(crate) ides: ::std::option::Option<::std::vec::Vec<crate::types::IdeConfiguration>>,
    pub(crate) instance_type: ::std::option::Option<crate::types::InstanceType>,
    pub(crate) inactivity_timeout_minutes: ::std::option::Option<i32>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateDevEnvironmentOutputBuilder {
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn space_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.space_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_space_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.space_name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_space_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.space_name
    }
    /// <p>The name of the project in the space.</p>
    /// This field is required.
    pub fn project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn set_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_name = input;
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn get_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_name
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// Appends an item to `ides`.
    ///
    /// To override the contents of this collection use [`set_ides`](Self::set_ides).
    ///
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub fn ides(mut self, input: crate::types::IdeConfiguration) -> Self {
        let mut v = self.ides.unwrap_or_default();
        v.push(input);
        self.ides = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub fn set_ides(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IdeConfiguration>>) -> Self {
        self.ides = input;
        self
    }
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub fn get_ides(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IdeConfiguration>> {
        &self.ides
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn instance_type(mut self, input: crate::types::InstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::InstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::InstanceType> {
        &self.instance_type
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn inactivity_timeout_minutes(mut self, input: i32) -> Self {
        self.inactivity_timeout_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn set_inactivity_timeout_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inactivity_timeout_minutes = input;
        self
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn get_inactivity_timeout_minutes(&self) -> &::std::option::Option<i32> {
        &self.inactivity_timeout_minutes
    }
    /// <p>A user-specified idempotency token. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, the subsequent retries return the result from the original successful request and have no additional effect.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-specified idempotency token. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, the subsequent retries return the result from the original successful request and have no additional effect.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A user-specified idempotency token. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, the subsequent retries return the result from the original successful request and have no additional effect.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDevEnvironmentOutput`](crate::operation::update_dev_environment::UpdateDevEnvironmentOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::update_dev_environment::builders::UpdateDevEnvironmentOutputBuilder::id)
    /// - [`space_name`](crate::operation::update_dev_environment::builders::UpdateDevEnvironmentOutputBuilder::space_name)
    /// - [`project_name`](crate::operation::update_dev_environment::builders::UpdateDevEnvironmentOutputBuilder::project_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_dev_environment::UpdateDevEnvironmentOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_dev_environment::UpdateDevEnvironmentOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building UpdateDevEnvironmentOutput",
                )
            })?,
            space_name: self.space_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "space_name",
                    "space_name was not specified but it is required when building UpdateDevEnvironmentOutput",
                )
            })?,
            project_name: self.project_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "project_name",
                    "project_name was not specified but it is required when building UpdateDevEnvironmentOutput",
                )
            })?,
            alias: self.alias,
            ides: self.ides,
            instance_type: self.instance_type,
            inactivity_timeout_minutes: self.inactivity_timeout_minutes.unwrap_or_default(),
            client_token: self.client_token,
            _request_id: self._request_id,
        })
    }
}
