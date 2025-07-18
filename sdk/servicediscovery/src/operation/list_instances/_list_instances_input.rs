// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInstancesInput {
    /// <p>The ID of the service that you want to list instances for.</p>
    pub service_id: ::std::option::Option<::std::string::String>,
    /// <p>For the first <code>ListInstances</code> request, omit this value.</p>
    /// <p>If more than <code>MaxResults</code> instances match the specified criteria, you can submit another <code>ListInstances</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of instances that you want Cloud Map to return in the response to a <code>ListInstances</code> request. If you don't specify a value for <code>MaxResults</code>, Cloud Map returns up to 100 instances.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListInstancesInput {
    /// <p>The ID of the service that you want to list instances for.</p>
    pub fn service_id(&self) -> ::std::option::Option<&str> {
        self.service_id.as_deref()
    }
    /// <p>For the first <code>ListInstances</code> request, omit this value.</p>
    /// <p>If more than <code>MaxResults</code> instances match the specified criteria, you can submit another <code>ListInstances</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of instances that you want Cloud Map to return in the response to a <code>ListInstances</code> request. If you don't specify a value for <code>MaxResults</code>, Cloud Map returns up to 100 instances.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListInstancesInput {
    /// Creates a new builder-style object to manufacture [`ListInstancesInput`](crate::operation::list_instances::ListInstancesInput).
    pub fn builder() -> crate::operation::list_instances::builders::ListInstancesInputBuilder {
        crate::operation::list_instances::builders::ListInstancesInputBuilder::default()
    }
}

/// A builder for [`ListInstancesInput`](crate::operation::list_instances::ListInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInstancesInputBuilder {
    pub(crate) service_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListInstancesInputBuilder {
    /// <p>The ID of the service that you want to list instances for.</p>
    /// This field is required.
    pub fn service_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service that you want to list instances for.</p>
    pub fn set_service_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_id = input;
        self
    }
    /// <p>The ID of the service that you want to list instances for.</p>
    pub fn get_service_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_id
    }
    /// <p>For the first <code>ListInstances</code> request, omit this value.</p>
    /// <p>If more than <code>MaxResults</code> instances match the specified criteria, you can submit another <code>ListInstances</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For the first <code>ListInstances</code> request, omit this value.</p>
    /// <p>If more than <code>MaxResults</code> instances match the specified criteria, you can submit another <code>ListInstances</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>For the first <code>ListInstances</code> request, omit this value.</p>
    /// <p>If more than <code>MaxResults</code> instances match the specified criteria, you can submit another <code>ListInstances</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of instances that you want Cloud Map to return in the response to a <code>ListInstances</code> request. If you don't specify a value for <code>MaxResults</code>, Cloud Map returns up to 100 instances.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of instances that you want Cloud Map to return in the response to a <code>ListInstances</code> request. If you don't specify a value for <code>MaxResults</code>, Cloud Map returns up to 100 instances.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of instances that you want Cloud Map to return in the response to a <code>ListInstances</code> request. If you don't specify a value for <code>MaxResults</code>, Cloud Map returns up to 100 instances.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListInstancesInput`](crate::operation::list_instances::ListInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_instances::ListInstancesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_instances::ListInstancesInput {
            service_id: self.service_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
