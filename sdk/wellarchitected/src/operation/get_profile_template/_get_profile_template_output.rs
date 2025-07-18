// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProfileTemplateOutput {
    /// <p>The profile template.</p>
    pub profile_template: ::std::option::Option<crate::types::ProfileTemplate>,
    _request_id: Option<String>,
}
impl GetProfileTemplateOutput {
    /// <p>The profile template.</p>
    pub fn profile_template(&self) -> ::std::option::Option<&crate::types::ProfileTemplate> {
        self.profile_template.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetProfileTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetProfileTemplateOutput {
    /// Creates a new builder-style object to manufacture [`GetProfileTemplateOutput`](crate::operation::get_profile_template::GetProfileTemplateOutput).
    pub fn builder() -> crate::operation::get_profile_template::builders::GetProfileTemplateOutputBuilder {
        crate::operation::get_profile_template::builders::GetProfileTemplateOutputBuilder::default()
    }
}

/// A builder for [`GetProfileTemplateOutput`](crate::operation::get_profile_template::GetProfileTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProfileTemplateOutputBuilder {
    pub(crate) profile_template: ::std::option::Option<crate::types::ProfileTemplate>,
    _request_id: Option<String>,
}
impl GetProfileTemplateOutputBuilder {
    /// <p>The profile template.</p>
    pub fn profile_template(mut self, input: crate::types::ProfileTemplate) -> Self {
        self.profile_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>The profile template.</p>
    pub fn set_profile_template(mut self, input: ::std::option::Option<crate::types::ProfileTemplate>) -> Self {
        self.profile_template = input;
        self
    }
    /// <p>The profile template.</p>
    pub fn get_profile_template(&self) -> &::std::option::Option<crate::types::ProfileTemplate> {
        &self.profile_template
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetProfileTemplateOutput`](crate::operation::get_profile_template::GetProfileTemplateOutput).
    pub fn build(self) -> crate::operation::get_profile_template::GetProfileTemplateOutput {
        crate::operation::get_profile_template::GetProfileTemplateOutput {
            profile_template: self.profile_template,
            _request_id: self._request_id,
        }
    }
}
