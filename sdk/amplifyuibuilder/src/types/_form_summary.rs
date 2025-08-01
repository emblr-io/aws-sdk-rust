// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the basic information about a form.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FormSummary {
    /// <p>The unique ID for the app associated with the form summary.</p>
    pub app_id: ::std::string::String,
    /// <p>The form's data source type.</p>
    pub data_type: ::std::option::Option<crate::types::FormDataTypeConfig>,
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    pub environment_name: ::std::string::String,
    /// <p>The type of operation to perform on the form.</p>
    pub form_action_type: crate::types::FormActionType,
    /// <p>The ID of the form.</p>
    pub id: ::std::string::String,
    /// <p>The name of the form.</p>
    pub name: ::std::string::String,
}
impl FormSummary {
    /// <p>The unique ID for the app associated with the form summary.</p>
    pub fn app_id(&self) -> &str {
        use std::ops::Deref;
        self.app_id.deref()
    }
    /// <p>The form's data source type.</p>
    pub fn data_type(&self) -> ::std::option::Option<&crate::types::FormDataTypeConfig> {
        self.data_type.as_ref()
    }
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    pub fn environment_name(&self) -> &str {
        use std::ops::Deref;
        self.environment_name.deref()
    }
    /// <p>The type of operation to perform on the form.</p>
    pub fn form_action_type(&self) -> &crate::types::FormActionType {
        &self.form_action_type
    }
    /// <p>The ID of the form.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the form.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
}
impl FormSummary {
    /// Creates a new builder-style object to manufacture [`FormSummary`](crate::types::FormSummary).
    pub fn builder() -> crate::types::builders::FormSummaryBuilder {
        crate::types::builders::FormSummaryBuilder::default()
    }
}

/// A builder for [`FormSummary`](crate::types::FormSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FormSummaryBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_type: ::std::option::Option<crate::types::FormDataTypeConfig>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) form_action_type: ::std::option::Option<crate::types::FormActionType>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl FormSummaryBuilder {
    /// <p>The unique ID for the app associated with the form summary.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the app associated with the form summary.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique ID for the app associated with the form summary.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The form's data source type.</p>
    /// This field is required.
    pub fn data_type(mut self, input: crate::types::FormDataTypeConfig) -> Self {
        self.data_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The form's data source type.</p>
    pub fn set_data_type(mut self, input: ::std::option::Option<crate::types::FormDataTypeConfig>) -> Self {
        self.data_type = input;
        self
    }
    /// <p>The form's data source type.</p>
    pub fn get_data_type(&self) -> &::std::option::Option<crate::types::FormDataTypeConfig> {
        &self.data_type
    }
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    /// This field is required.
    pub fn environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    pub fn set_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_name = input;
        self
    }
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    pub fn get_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_name
    }
    /// <p>The type of operation to perform on the form.</p>
    /// This field is required.
    pub fn form_action_type(mut self, input: crate::types::FormActionType) -> Self {
        self.form_action_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of operation to perform on the form.</p>
    pub fn set_form_action_type(mut self, input: ::std::option::Option<crate::types::FormActionType>) -> Self {
        self.form_action_type = input;
        self
    }
    /// <p>The type of operation to perform on the form.</p>
    pub fn get_form_action_type(&self) -> &::std::option::Option<crate::types::FormActionType> {
        &self.form_action_type
    }
    /// <p>The ID of the form.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the form.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the form.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the form.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the form.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the form.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`FormSummary`](crate::types::FormSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`app_id`](crate::types::builders::FormSummaryBuilder::app_id)
    /// - [`environment_name`](crate::types::builders::FormSummaryBuilder::environment_name)
    /// - [`form_action_type`](crate::types::builders::FormSummaryBuilder::form_action_type)
    /// - [`id`](crate::types::builders::FormSummaryBuilder::id)
    /// - [`name`](crate::types::builders::FormSummaryBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::FormSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FormSummary {
            app_id: self.app_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_id",
                    "app_id was not specified but it is required when building FormSummary",
                )
            })?,
            data_type: self.data_type,
            environment_name: self.environment_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "environment_name",
                    "environment_name was not specified but it is required when building FormSummary",
                )
            })?,
            form_action_type: self.form_action_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "form_action_type",
                    "form_action_type was not specified but it is required when building FormSummary",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building FormSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building FormSummary",
                )
            })?,
        })
    }
}
