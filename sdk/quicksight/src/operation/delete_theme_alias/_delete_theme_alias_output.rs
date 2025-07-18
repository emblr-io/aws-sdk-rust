// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteThemeAliasOutput {
    /// <p>The name for the theme alias.</p>
    pub alias_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the theme resource using the deleted alias.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    /// <p>An ID for the theme associated with the deletion.</p>
    pub theme_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteThemeAliasOutput {
    /// <p>The name for the theme alias.</p>
    pub fn alias_name(&self) -> ::std::option::Option<&str> {
        self.alias_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the theme resource using the deleted alias.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
    /// <p>An ID for the theme associated with the deletion.</p>
    pub fn theme_id(&self) -> ::std::option::Option<&str> {
        self.theme_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteThemeAliasOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteThemeAliasOutput {
    /// Creates a new builder-style object to manufacture [`DeleteThemeAliasOutput`](crate::operation::delete_theme_alias::DeleteThemeAliasOutput).
    pub fn builder() -> crate::operation::delete_theme_alias::builders::DeleteThemeAliasOutputBuilder {
        crate::operation::delete_theme_alias::builders::DeleteThemeAliasOutputBuilder::default()
    }
}

/// A builder for [`DeleteThemeAliasOutput`](crate::operation::delete_theme_alias::DeleteThemeAliasOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteThemeAliasOutputBuilder {
    pub(crate) alias_name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<i32>,
    pub(crate) theme_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteThemeAliasOutputBuilder {
    /// <p>The name for the theme alias.</p>
    pub fn alias_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the theme alias.</p>
    pub fn set_alias_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias_name = input;
        self
    }
    /// <p>The name for the theme alias.</p>
    pub fn get_alias_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias_name
    }
    /// <p>The Amazon Resource Name (ARN) of the theme resource using the deleted alias.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the theme resource using the deleted alias.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the theme resource using the deleted alias.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(mut self, input: i32) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<i32> {
        &self.status
    }
    /// <p>An ID for the theme associated with the deletion.</p>
    pub fn theme_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.theme_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An ID for the theme associated with the deletion.</p>
    pub fn set_theme_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.theme_id = input;
        self
    }
    /// <p>An ID for the theme associated with the deletion.</p>
    pub fn get_theme_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.theme_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteThemeAliasOutput`](crate::operation::delete_theme_alias::DeleteThemeAliasOutput).
    pub fn build(self) -> crate::operation::delete_theme_alias::DeleteThemeAliasOutput {
        crate::operation::delete_theme_alias::DeleteThemeAliasOutput {
            alias_name: self.alias_name,
            arn: self.arn,
            request_id: self.request_id,
            status: self.status.unwrap_or_default(),
            theme_id: self.theme_id,
            _request_id: self._request_id,
        }
    }
}
