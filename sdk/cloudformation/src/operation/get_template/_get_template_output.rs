// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output for <code>GetTemplate</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTemplateOutput {
    /// <p>Structure that contains the template body.</p>
    /// <p>CloudFormation returns the same template that was used when the stack was created.</p>
    pub template_body: ::std::option::Option<::std::string::String>,
    /// <p>The stage of the template that you can retrieve. For stacks, the <code>Original</code> and <code>Processed</code> templates are always available. For change sets, the <code>Original</code> template is always available. After CloudFormation finishes creating the change set, the <code>Processed</code> template becomes available.</p>
    pub stages_available: ::std::option::Option<::std::vec::Vec<crate::types::TemplateStage>>,
    _request_id: Option<String>,
}
impl GetTemplateOutput {
    /// <p>Structure that contains the template body.</p>
    /// <p>CloudFormation returns the same template that was used when the stack was created.</p>
    pub fn template_body(&self) -> ::std::option::Option<&str> {
        self.template_body.as_deref()
    }
    /// <p>The stage of the template that you can retrieve. For stacks, the <code>Original</code> and <code>Processed</code> templates are always available. For change sets, the <code>Original</code> template is always available. After CloudFormation finishes creating the change set, the <code>Processed</code> template becomes available.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stages_available.is_none()`.
    pub fn stages_available(&self) -> &[crate::types::TemplateStage] {
        self.stages_available.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTemplateOutput {
    /// Creates a new builder-style object to manufacture [`GetTemplateOutput`](crate::operation::get_template::GetTemplateOutput).
    pub fn builder() -> crate::operation::get_template::builders::GetTemplateOutputBuilder {
        crate::operation::get_template::builders::GetTemplateOutputBuilder::default()
    }
}

/// A builder for [`GetTemplateOutput`](crate::operation::get_template::GetTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTemplateOutputBuilder {
    pub(crate) template_body: ::std::option::Option<::std::string::String>,
    pub(crate) stages_available: ::std::option::Option<::std::vec::Vec<crate::types::TemplateStage>>,
    _request_id: Option<String>,
}
impl GetTemplateOutputBuilder {
    /// <p>Structure that contains the template body.</p>
    /// <p>CloudFormation returns the same template that was used when the stack was created.</p>
    pub fn template_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Structure that contains the template body.</p>
    /// <p>CloudFormation returns the same template that was used when the stack was created.</p>
    pub fn set_template_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_body = input;
        self
    }
    /// <p>Structure that contains the template body.</p>
    /// <p>CloudFormation returns the same template that was used when the stack was created.</p>
    pub fn get_template_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_body
    }
    /// Appends an item to `stages_available`.
    ///
    /// To override the contents of this collection use [`set_stages_available`](Self::set_stages_available).
    ///
    /// <p>The stage of the template that you can retrieve. For stacks, the <code>Original</code> and <code>Processed</code> templates are always available. For change sets, the <code>Original</code> template is always available. After CloudFormation finishes creating the change set, the <code>Processed</code> template becomes available.</p>
    pub fn stages_available(mut self, input: crate::types::TemplateStage) -> Self {
        let mut v = self.stages_available.unwrap_or_default();
        v.push(input);
        self.stages_available = ::std::option::Option::Some(v);
        self
    }
    /// <p>The stage of the template that you can retrieve. For stacks, the <code>Original</code> and <code>Processed</code> templates are always available. For change sets, the <code>Original</code> template is always available. After CloudFormation finishes creating the change set, the <code>Processed</code> template becomes available.</p>
    pub fn set_stages_available(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TemplateStage>>) -> Self {
        self.stages_available = input;
        self
    }
    /// <p>The stage of the template that you can retrieve. For stacks, the <code>Original</code> and <code>Processed</code> templates are always available. For change sets, the <code>Original</code> template is always available. After CloudFormation finishes creating the change set, the <code>Processed</code> template becomes available.</p>
    pub fn get_stages_available(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TemplateStage>> {
        &self.stages_available
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTemplateOutput`](crate::operation::get_template::GetTemplateOutput).
    pub fn build(self) -> crate::operation::get_template::GetTemplateOutput {
        crate::operation::get_template::GetTemplateOutput {
            template_body: self.template_body,
            stages_available: self.stages_available,
            _request_id: self._request_id,
        }
    }
}
