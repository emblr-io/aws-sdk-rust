// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateQAppOutput {
    /// <p>The unique identifier of the updated Q App.</p>
    pub app_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the updated Q App.</p>
    pub app_arn: ::std::string::String,
    /// <p>The new title of the updated Q App.</p>
    pub title: ::std::string::String,
    /// <p>The new description of the updated Q App.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The initial prompt for the updated Q App.</p>
    pub initial_prompt: ::std::option::Option<::std::string::String>,
    /// <p>The new version of the updated Q App.</p>
    pub app_version: i32,
    /// <p>The status of the updated Q App.</p>
    pub status: crate::types::AppStatus,
    /// <p>The date and time the Q App was originally created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The user who originally created the Q App.</p>
    pub created_by: ::std::string::String,
    /// <p>The date and time the Q App was last updated.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    /// <p>The user who last updated the Q App.</p>
    pub updated_by: ::std::string::String,
    /// <p>The capabilities required for the updated Q App.</p>
    pub required_capabilities: ::std::option::Option<::std::vec::Vec<crate::types::AppRequiredCapability>>,
    _request_id: Option<String>,
}
impl UpdateQAppOutput {
    /// <p>The unique identifier of the updated Q App.</p>
    pub fn app_id(&self) -> &str {
        use std::ops::Deref;
        self.app_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the updated Q App.</p>
    pub fn app_arn(&self) -> &str {
        use std::ops::Deref;
        self.app_arn.deref()
    }
    /// <p>The new title of the updated Q App.</p>
    pub fn title(&self) -> &str {
        use std::ops::Deref;
        self.title.deref()
    }
    /// <p>The new description of the updated Q App.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The initial prompt for the updated Q App.</p>
    pub fn initial_prompt(&self) -> ::std::option::Option<&str> {
        self.initial_prompt.as_deref()
    }
    /// <p>The new version of the updated Q App.</p>
    pub fn app_version(&self) -> i32 {
        self.app_version
    }
    /// <p>The status of the updated Q App.</p>
    pub fn status(&self) -> &crate::types::AppStatus {
        &self.status
    }
    /// <p>The date and time the Q App was originally created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The user who originally created the Q App.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The date and time the Q App was last updated.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
    /// <p>The user who last updated the Q App.</p>
    pub fn updated_by(&self) -> &str {
        use std::ops::Deref;
        self.updated_by.deref()
    }
    /// <p>The capabilities required for the updated Q App.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.required_capabilities.is_none()`.
    pub fn required_capabilities(&self) -> &[crate::types::AppRequiredCapability] {
        self.required_capabilities.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for UpdateQAppOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateQAppOutput {
    /// Creates a new builder-style object to manufacture [`UpdateQAppOutput`](crate::operation::update_q_app::UpdateQAppOutput).
    pub fn builder() -> crate::operation::update_q_app::builders::UpdateQAppOutputBuilder {
        crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::default()
    }
}

/// A builder for [`UpdateQAppOutput`](crate::operation::update_q_app::UpdateQAppOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateQAppOutputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) app_arn: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) initial_prompt: ::std::option::Option<::std::string::String>,
    pub(crate) app_version: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::AppStatus>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_by: ::std::option::Option<::std::string::String>,
    pub(crate) required_capabilities: ::std::option::Option<::std::vec::Vec<crate::types::AppRequiredCapability>>,
    _request_id: Option<String>,
}
impl UpdateQAppOutputBuilder {
    /// <p>The unique identifier of the updated Q App.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the updated Q App.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique identifier of the updated Q App.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The Amazon Resource Name (ARN) of the updated Q App.</p>
    /// This field is required.
    pub fn app_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the updated Q App.</p>
    pub fn set_app_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the updated Q App.</p>
    pub fn get_app_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_arn
    }
    /// <p>The new title of the updated Q App.</p>
    /// This field is required.
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new title of the updated Q App.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The new title of the updated Q App.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The new description of the updated Q App.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new description of the updated Q App.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The new description of the updated Q App.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The initial prompt for the updated Q App.</p>
    pub fn initial_prompt(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.initial_prompt = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The initial prompt for the updated Q App.</p>
    pub fn set_initial_prompt(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.initial_prompt = input;
        self
    }
    /// <p>The initial prompt for the updated Q App.</p>
    pub fn get_initial_prompt(&self) -> &::std::option::Option<::std::string::String> {
        &self.initial_prompt
    }
    /// <p>The new version of the updated Q App.</p>
    /// This field is required.
    pub fn app_version(mut self, input: i32) -> Self {
        self.app_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new version of the updated Q App.</p>
    pub fn set_app_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.app_version = input;
        self
    }
    /// <p>The new version of the updated Q App.</p>
    pub fn get_app_version(&self) -> &::std::option::Option<i32> {
        &self.app_version
    }
    /// <p>The status of the updated Q App.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::AppStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the updated Q App.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AppStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the updated Q App.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AppStatus> {
        &self.status
    }
    /// <p>The date and time the Q App was originally created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the Q App was originally created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time the Q App was originally created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The user who originally created the Q App.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who originally created the Q App.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The user who originally created the Q App.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The date and time the Q App was last updated.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the Q App was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time the Q App was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The user who last updated the Q App.</p>
    /// This field is required.
    pub fn updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who last updated the Q App.</p>
    pub fn set_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.updated_by = input;
        self
    }
    /// <p>The user who last updated the Q App.</p>
    pub fn get_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.updated_by
    }
    /// Appends an item to `required_capabilities`.
    ///
    /// To override the contents of this collection use [`set_required_capabilities`](Self::set_required_capabilities).
    ///
    /// <p>The capabilities required for the updated Q App.</p>
    pub fn required_capabilities(mut self, input: crate::types::AppRequiredCapability) -> Self {
        let mut v = self.required_capabilities.unwrap_or_default();
        v.push(input);
        self.required_capabilities = ::std::option::Option::Some(v);
        self
    }
    /// <p>The capabilities required for the updated Q App.</p>
    pub fn set_required_capabilities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AppRequiredCapability>>) -> Self {
        self.required_capabilities = input;
        self
    }
    /// <p>The capabilities required for the updated Q App.</p>
    pub fn get_required_capabilities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AppRequiredCapability>> {
        &self.required_capabilities
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateQAppOutput`](crate::operation::update_q_app::UpdateQAppOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`app_id`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::app_id)
    /// - [`app_arn`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::app_arn)
    /// - [`title`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::title)
    /// - [`app_version`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::app_version)
    /// - [`status`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::status)
    /// - [`created_at`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::created_at)
    /// - [`created_by`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::created_by)
    /// - [`updated_at`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::updated_at)
    /// - [`updated_by`](crate::operation::update_q_app::builders::UpdateQAppOutputBuilder::updated_by)
    pub fn build(self) -> ::std::result::Result<crate::operation::update_q_app::UpdateQAppOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_q_app::UpdateQAppOutput {
            app_id: self.app_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_id",
                    "app_id was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            app_arn: self.app_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_arn",
                    "app_arn was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            title: self.title.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "title",
                    "title was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            description: self.description,
            initial_prompt: self.initial_prompt,
            app_version: self.app_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_version",
                    "app_version was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            updated_by: self.updated_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_by",
                    "updated_by was not specified but it is required when building UpdateQAppOutput",
                )
            })?,
            required_capabilities: self.required_capabilities,
            _request_id: self._request_id,
        })
    }
}
