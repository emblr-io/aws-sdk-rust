// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTemplateAliasOutput {
    /// <p>Information about the template alias.</p>
    pub template_alias: ::std::option::Option<crate::types::TemplateAlias>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTemplateAliasOutput {
    /// <p>Information about the template alias.</p>
    pub fn template_alias(&self) -> ::std::option::Option<&crate::types::TemplateAlias> {
        self.template_alias.as_ref()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateTemplateAliasOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateTemplateAliasOutput {
    /// Creates a new builder-style object to manufacture [`CreateTemplateAliasOutput`](crate::operation::create_template_alias::CreateTemplateAliasOutput).
    pub fn builder() -> crate::operation::create_template_alias::builders::CreateTemplateAliasOutputBuilder {
        crate::operation::create_template_alias::builders::CreateTemplateAliasOutputBuilder::default()
    }
}

/// A builder for [`CreateTemplateAliasOutput`](crate::operation::create_template_alias::CreateTemplateAliasOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTemplateAliasOutputBuilder {
    pub(crate) template_alias: ::std::option::Option<crate::types::TemplateAlias>,
    pub(crate) status: ::std::option::Option<i32>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTemplateAliasOutputBuilder {
    /// <p>Information about the template alias.</p>
    pub fn template_alias(mut self, input: crate::types::TemplateAlias) -> Self {
        self.template_alias = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the template alias.</p>
    pub fn set_template_alias(mut self, input: ::std::option::Option<crate::types::TemplateAlias>) -> Self {
        self.template_alias = input;
        self
    }
    /// <p>Information about the template alias.</p>
    pub fn get_template_alias(&self) -> &::std::option::Option<crate::types::TemplateAlias> {
        &self.template_alias
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateTemplateAliasOutput`](crate::operation::create_template_alias::CreateTemplateAliasOutput).
    pub fn build(self) -> crate::operation::create_template_alias::CreateTemplateAliasOutput {
        crate::operation::create_template_alias::CreateTemplateAliasOutput {
            template_alias: self.template_alias,
            status: self.status.unwrap_or_default(),
            request_id: self.request_id,
            _request_id: self._request_id,
        }
    }
}
