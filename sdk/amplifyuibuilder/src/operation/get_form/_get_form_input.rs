// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFormInput {
    /// <p>The unique ID of the Amplify app.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    pub environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID of the form.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetFormInput {
    /// <p>The unique ID of the Amplify app.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The name of the backend environment that is part of the Amplify app.</p>
    pub fn environment_name(&self) -> ::std::option::Option<&str> {
        self.environment_name.as_deref()
    }
    /// <p>The unique ID of the form.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetFormInput {
    /// Creates a new builder-style object to manufacture [`GetFormInput`](crate::operation::get_form::GetFormInput).
    pub fn builder() -> crate::operation::get_form::builders::GetFormInputBuilder {
        crate::operation::get_form::builders::GetFormInputBuilder::default()
    }
}

/// A builder for [`GetFormInput`](crate::operation::get_form::GetFormInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFormInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetFormInputBuilder {
    /// <p>The unique ID of the Amplify app.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the Amplify app.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique ID of the Amplify app.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
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
    /// <p>The unique ID of the form.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the form.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID of the form.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetFormInput`](crate::operation::get_form::GetFormInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_form::GetFormInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_form::GetFormInput {
            app_id: self.app_id,
            environment_name: self.environment_name,
            id: self.id,
        })
    }
}
