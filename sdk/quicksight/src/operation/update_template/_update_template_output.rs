// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTemplateOutput {
    /// <p>The ID for the template.</p>
    pub template_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for the template.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN for the template, including the version information of the first version.</p>
    pub version_arn: ::std::option::Option<::std::string::String>,
    /// <p>The creation status of the template.</p>
    pub creation_status: ::std::option::Option<crate::types::ResourceStatus>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateTemplateOutput {
    /// <p>The ID for the template.</p>
    pub fn template_id(&self) -> ::std::option::Option<&str> {
        self.template_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the template.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ARN for the template, including the version information of the first version.</p>
    pub fn version_arn(&self) -> ::std::option::Option<&str> {
        self.version_arn.as_deref()
    }
    /// <p>The creation status of the template.</p>
    pub fn creation_status(&self) -> ::std::option::Option<&crate::types::ResourceStatus> {
        self.creation_status.as_ref()
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
impl ::aws_types::request_id::RequestId for UpdateTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateTemplateOutput {
    /// Creates a new builder-style object to manufacture [`UpdateTemplateOutput`](crate::operation::update_template::UpdateTemplateOutput).
    pub fn builder() -> crate::operation::update_template::builders::UpdateTemplateOutputBuilder {
        crate::operation::update_template::builders::UpdateTemplateOutputBuilder::default()
    }
}

/// A builder for [`UpdateTemplateOutput`](crate::operation::update_template::UpdateTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTemplateOutputBuilder {
    pub(crate) template_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_status: ::std::option::Option<crate::types::ResourceStatus>,
    pub(crate) status: ::std::option::Option<i32>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateTemplateOutputBuilder {
    /// <p>The ID for the template.</p>
    pub fn template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the template.</p>
    pub fn set_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_id = input;
        self
    }
    /// <p>The ID for the template.</p>
    pub fn get_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_id
    }
    /// <p>The Amazon Resource Name (ARN) for the template.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the template.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the template.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ARN for the template, including the version information of the first version.</p>
    pub fn version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the template, including the version information of the first version.</p>
    pub fn set_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_arn = input;
        self
    }
    /// <p>The ARN for the template, including the version information of the first version.</p>
    pub fn get_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_arn
    }
    /// <p>The creation status of the template.</p>
    pub fn creation_status(mut self, input: crate::types::ResourceStatus) -> Self {
        self.creation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation status of the template.</p>
    pub fn set_creation_status(mut self, input: ::std::option::Option<crate::types::ResourceStatus>) -> Self {
        self.creation_status = input;
        self
    }
    /// <p>The creation status of the template.</p>
    pub fn get_creation_status(&self) -> &::std::option::Option<crate::types::ResourceStatus> {
        &self.creation_status
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
    /// Consumes the builder and constructs a [`UpdateTemplateOutput`](crate::operation::update_template::UpdateTemplateOutput).
    pub fn build(self) -> crate::operation::update_template::UpdateTemplateOutput {
        crate::operation::update_template::UpdateTemplateOutput {
            template_id: self.template_id,
            arn: self.arn,
            version_arn: self.version_arn,
            creation_status: self.creation_status,
            status: self.status.unwrap_or_default(),
            request_id: self.request_id,
            _request_id: self._request_id,
        }
    }
}
