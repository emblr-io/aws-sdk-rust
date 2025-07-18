// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateNotebookInstanceOutput {
    /// <p>The Amazon Resource Name (ARN) of the notebook instance.</p>
    pub notebook_instance_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateNotebookInstanceOutput {
    /// <p>The Amazon Resource Name (ARN) of the notebook instance.</p>
    pub fn notebook_instance_arn(&self) -> ::std::option::Option<&str> {
        self.notebook_instance_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateNotebookInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateNotebookInstanceOutput {
    /// Creates a new builder-style object to manufacture [`CreateNotebookInstanceOutput`](crate::operation::create_notebook_instance::CreateNotebookInstanceOutput).
    pub fn builder() -> crate::operation::create_notebook_instance::builders::CreateNotebookInstanceOutputBuilder {
        crate::operation::create_notebook_instance::builders::CreateNotebookInstanceOutputBuilder::default()
    }
}

/// A builder for [`CreateNotebookInstanceOutput`](crate::operation::create_notebook_instance::CreateNotebookInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateNotebookInstanceOutputBuilder {
    pub(crate) notebook_instance_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateNotebookInstanceOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the notebook instance.</p>
    pub fn notebook_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notebook_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the notebook instance.</p>
    pub fn set_notebook_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notebook_instance_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the notebook instance.</p>
    pub fn get_notebook_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.notebook_instance_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateNotebookInstanceOutput`](crate::operation::create_notebook_instance::CreateNotebookInstanceOutput).
    pub fn build(self) -> crate::operation::create_notebook_instance::CreateNotebookInstanceOutput {
        crate::operation::create_notebook_instance::CreateNotebookInstanceOutput {
            notebook_instance_arn: self.notebook_instance_arn,
            _request_id: self._request_id,
        }
    }
}
