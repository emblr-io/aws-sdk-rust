// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourceEvaluationsOutput {
    /// <p>Returns a <code>ResourceEvaluations</code> object.</p>
    pub resource_evaluations: ::std::option::Option<::std::vec::Vec<crate::types::ResourceEvaluation>>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListResourceEvaluationsOutput {
    /// <p>Returns a <code>ResourceEvaluations</code> object.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_evaluations.is_none()`.
    pub fn resource_evaluations(&self) -> &[crate::types::ResourceEvaluation] {
        self.resource_evaluations.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListResourceEvaluationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListResourceEvaluationsOutput {
    /// Creates a new builder-style object to manufacture [`ListResourceEvaluationsOutput`](crate::operation::list_resource_evaluations::ListResourceEvaluationsOutput).
    pub fn builder() -> crate::operation::list_resource_evaluations::builders::ListResourceEvaluationsOutputBuilder {
        crate::operation::list_resource_evaluations::builders::ListResourceEvaluationsOutputBuilder::default()
    }
}

/// A builder for [`ListResourceEvaluationsOutput`](crate::operation::list_resource_evaluations::ListResourceEvaluationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourceEvaluationsOutputBuilder {
    pub(crate) resource_evaluations: ::std::option::Option<::std::vec::Vec<crate::types::ResourceEvaluation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListResourceEvaluationsOutputBuilder {
    /// Appends an item to `resource_evaluations`.
    ///
    /// To override the contents of this collection use [`set_resource_evaluations`](Self::set_resource_evaluations).
    ///
    /// <p>Returns a <code>ResourceEvaluations</code> object.</p>
    pub fn resource_evaluations(mut self, input: crate::types::ResourceEvaluation) -> Self {
        let mut v = self.resource_evaluations.unwrap_or_default();
        v.push(input);
        self.resource_evaluations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns a <code>ResourceEvaluations</code> object.</p>
    pub fn set_resource_evaluations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceEvaluation>>) -> Self {
        self.resource_evaluations = input;
        self
    }
    /// <p>Returns a <code>ResourceEvaluations</code> object.</p>
    pub fn get_resource_evaluations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceEvaluation>> {
        &self.resource_evaluations
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListResourceEvaluationsOutput`](crate::operation::list_resource_evaluations::ListResourceEvaluationsOutput).
    pub fn build(self) -> crate::operation::list_resource_evaluations::ListResourceEvaluationsOutput {
        crate::operation::list_resource_evaluations::ListResourceEvaluationsOutput {
            resource_evaluations: self.resource_evaluations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
