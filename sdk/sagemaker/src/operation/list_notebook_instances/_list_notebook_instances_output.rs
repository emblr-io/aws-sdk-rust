// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListNotebookInstancesOutput {
    /// <p>If the response to the previous <code>ListNotebookInstances</code> request was truncated, SageMaker AI returns this token. To retrieve the next set of notebook instances, use the token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>NotebookInstanceSummary</code> objects, one for each notebook instance.</p>
    pub notebook_instances: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceSummary>>,
    _request_id: Option<String>,
}
impl ListNotebookInstancesOutput {
    /// <p>If the response to the previous <code>ListNotebookInstances</code> request was truncated, SageMaker AI returns this token. To retrieve the next set of notebook instances, use the token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of <code>NotebookInstanceSummary</code> objects, one for each notebook instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notebook_instances.is_none()`.
    pub fn notebook_instances(&self) -> &[crate::types::NotebookInstanceSummary] {
        self.notebook_instances.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListNotebookInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListNotebookInstancesOutput {
    /// Creates a new builder-style object to manufacture [`ListNotebookInstancesOutput`](crate::operation::list_notebook_instances::ListNotebookInstancesOutput).
    pub fn builder() -> crate::operation::list_notebook_instances::builders::ListNotebookInstancesOutputBuilder {
        crate::operation::list_notebook_instances::builders::ListNotebookInstancesOutputBuilder::default()
    }
}

/// A builder for [`ListNotebookInstancesOutput`](crate::operation::list_notebook_instances::ListNotebookInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListNotebookInstancesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) notebook_instances: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceSummary>>,
    _request_id: Option<String>,
}
impl ListNotebookInstancesOutputBuilder {
    /// <p>If the response to the previous <code>ListNotebookInstances</code> request was truncated, SageMaker AI returns this token. To retrieve the next set of notebook instances, use the token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response to the previous <code>ListNotebookInstances</code> request was truncated, SageMaker AI returns this token. To retrieve the next set of notebook instances, use the token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response to the previous <code>ListNotebookInstances</code> request was truncated, SageMaker AI returns this token. To retrieve the next set of notebook instances, use the token in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `notebook_instances`.
    ///
    /// To override the contents of this collection use [`set_notebook_instances`](Self::set_notebook_instances).
    ///
    /// <p>An array of <code>NotebookInstanceSummary</code> objects, one for each notebook instance.</p>
    pub fn notebook_instances(mut self, input: crate::types::NotebookInstanceSummary) -> Self {
        let mut v = self.notebook_instances.unwrap_or_default();
        v.push(input);
        self.notebook_instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>NotebookInstanceSummary</code> objects, one for each notebook instance.</p>
    pub fn set_notebook_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceSummary>>) -> Self {
        self.notebook_instances = input;
        self
    }
    /// <p>An array of <code>NotebookInstanceSummary</code> objects, one for each notebook instance.</p>
    pub fn get_notebook_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceSummary>> {
        &self.notebook_instances
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListNotebookInstancesOutput`](crate::operation::list_notebook_instances::ListNotebookInstancesOutput).
    pub fn build(self) -> crate::operation::list_notebook_instances::ListNotebookInstancesOutput {
        crate::operation::list_notebook_instances::ListNotebookInstancesOutput {
            next_token: self.next_token,
            notebook_instances: self.notebook_instances,
            _request_id: self._request_id,
        }
    }
}
