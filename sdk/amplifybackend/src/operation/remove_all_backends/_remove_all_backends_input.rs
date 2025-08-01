// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request body for RemoveAllBackends.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveAllBackendsInput {
    /// <p>The app ID.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>Cleans up the Amplify Console app if this value is set to true.</p>
    pub clean_amplify_app: ::std::option::Option<bool>,
}
impl RemoveAllBackendsInput {
    /// <p>The app ID.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>Cleans up the Amplify Console app if this value is set to true.</p>
    pub fn clean_amplify_app(&self) -> ::std::option::Option<bool> {
        self.clean_amplify_app
    }
}
impl RemoveAllBackendsInput {
    /// Creates a new builder-style object to manufacture [`RemoveAllBackendsInput`](crate::operation::remove_all_backends::RemoveAllBackendsInput).
    pub fn builder() -> crate::operation::remove_all_backends::builders::RemoveAllBackendsInputBuilder {
        crate::operation::remove_all_backends::builders::RemoveAllBackendsInputBuilder::default()
    }
}

/// A builder for [`RemoveAllBackendsInput`](crate::operation::remove_all_backends::RemoveAllBackendsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveAllBackendsInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) clean_amplify_app: ::std::option::Option<bool>,
}
impl RemoveAllBackendsInputBuilder {
    /// <p>The app ID.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app ID.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The app ID.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>Cleans up the Amplify Console app if this value is set to true.</p>
    pub fn clean_amplify_app(mut self, input: bool) -> Self {
        self.clean_amplify_app = ::std::option::Option::Some(input);
        self
    }
    /// <p>Cleans up the Amplify Console app if this value is set to true.</p>
    pub fn set_clean_amplify_app(mut self, input: ::std::option::Option<bool>) -> Self {
        self.clean_amplify_app = input;
        self
    }
    /// <p>Cleans up the Amplify Console app if this value is set to true.</p>
    pub fn get_clean_amplify_app(&self) -> &::std::option::Option<bool> {
        &self.clean_amplify_app
    }
    /// Consumes the builder and constructs a [`RemoveAllBackendsInput`](crate::operation::remove_all_backends::RemoveAllBackendsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::remove_all_backends::RemoveAllBackendsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::remove_all_backends::RemoveAllBackendsInput {
            app_id: self.app_id,
            clean_amplify_app: self.clean_amplify_app,
        })
    }
}
