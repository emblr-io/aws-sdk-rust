// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateComponentTypeOutput {
    /// <p>The ID of the workspace that contains the component type.</p>
    pub workspace_id: ::std::string::String,
    /// <p>The ARN of the component type.</p>
    pub arn: ::std::string::String,
    /// <p>The ID of the component type.</p>
    pub component_type_id: ::std::string::String,
    /// <p>The current state of the component type.</p>
    pub state: crate::types::State,
    _request_id: Option<String>,
}
impl UpdateComponentTypeOutput {
    /// <p>The ID of the workspace that contains the component type.</p>
    pub fn workspace_id(&self) -> &str {
        use std::ops::Deref;
        self.workspace_id.deref()
    }
    /// <p>The ARN of the component type.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The ID of the component type.</p>
    pub fn component_type_id(&self) -> &str {
        use std::ops::Deref;
        self.component_type_id.deref()
    }
    /// <p>The current state of the component type.</p>
    pub fn state(&self) -> &crate::types::State {
        &self.state
    }
}
impl ::aws_types::request_id::RequestId for UpdateComponentTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateComponentTypeOutput {
    /// Creates a new builder-style object to manufacture [`UpdateComponentTypeOutput`](crate::operation::update_component_type::UpdateComponentTypeOutput).
    pub fn builder() -> crate::operation::update_component_type::builders::UpdateComponentTypeOutputBuilder {
        crate::operation::update_component_type::builders::UpdateComponentTypeOutputBuilder::default()
    }
}

/// A builder for [`UpdateComponentTypeOutput`](crate::operation::update_component_type::UpdateComponentTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateComponentTypeOutputBuilder {
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) component_type_id: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::State>,
    _request_id: Option<String>,
}
impl UpdateComponentTypeOutputBuilder {
    /// <p>The ID of the workspace that contains the component type.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workspace that contains the component type.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The ID of the workspace that contains the component type.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// <p>The ARN of the component type.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the component type.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the component type.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of the component type.</p>
    /// This field is required.
    pub fn component_type_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_type_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the component type.</p>
    pub fn set_component_type_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_type_id = input;
        self
    }
    /// <p>The ID of the component type.</p>
    pub fn get_component_type_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_type_id
    }
    /// <p>The current state of the component type.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::State) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the component type.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::State>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of the component type.</p>
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
    /// Consumes the builder and constructs a [`UpdateComponentTypeOutput`](crate::operation::update_component_type::UpdateComponentTypeOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`workspace_id`](crate::operation::update_component_type::builders::UpdateComponentTypeOutputBuilder::workspace_id)
    /// - [`arn`](crate::operation::update_component_type::builders::UpdateComponentTypeOutputBuilder::arn)
    /// - [`component_type_id`](crate::operation::update_component_type::builders::UpdateComponentTypeOutputBuilder::component_type_id)
    /// - [`state`](crate::operation::update_component_type::builders::UpdateComponentTypeOutputBuilder::state)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_component_type::UpdateComponentTypeOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_component_type::UpdateComponentTypeOutput {
            workspace_id: self.workspace_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workspace_id",
                    "workspace_id was not specified but it is required when building UpdateComponentTypeOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building UpdateComponentTypeOutput",
                )
            })?,
            component_type_id: self.component_type_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "component_type_id",
                    "component_type_id was not specified but it is required when building UpdateComponentTypeOutput",
                )
            })?,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building UpdateComponentTypeOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
