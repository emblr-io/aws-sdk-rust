// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInstanceTypesOutput {
    /// <p>The instance type.</p>
    pub instance_types: ::std::option::Option<::std::vec::Vec<crate::types::InstanceTypeInfo>>,
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeInstanceTypesOutput {
    /// <p>The instance type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_types.is_none()`.
    pub fn instance_types(&self) -> &[crate::types::InstanceTypeInfo] {
        self.instance_types.as_deref().unwrap_or_default()
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeInstanceTypesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeInstanceTypesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeInstanceTypesOutput`](crate::operation::describe_instance_types::DescribeInstanceTypesOutput).
    pub fn builder() -> crate::operation::describe_instance_types::builders::DescribeInstanceTypesOutputBuilder {
        crate::operation::describe_instance_types::builders::DescribeInstanceTypesOutputBuilder::default()
    }
}

/// A builder for [`DescribeInstanceTypesOutput`](crate::operation::describe_instance_types::DescribeInstanceTypesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInstanceTypesOutputBuilder {
    pub(crate) instance_types: ::std::option::Option<::std::vec::Vec<crate::types::InstanceTypeInfo>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeInstanceTypesOutputBuilder {
    /// Appends an item to `instance_types`.
    ///
    /// To override the contents of this collection use [`set_instance_types`](Self::set_instance_types).
    ///
    /// <p>The instance type.</p>
    pub fn instance_types(mut self, input: crate::types::InstanceTypeInfo) -> Self {
        let mut v = self.instance_types.unwrap_or_default();
        v.push(input);
        self.instance_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The instance type.</p>
    pub fn set_instance_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstanceTypeInfo>>) -> Self {
        self.instance_types = input;
        self
    }
    /// <p>The instance type.</p>
    pub fn get_instance_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstanceTypeInfo>> {
        &self.instance_types
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
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
    /// Consumes the builder and constructs a [`DescribeInstanceTypesOutput`](crate::operation::describe_instance_types::DescribeInstanceTypesOutput).
    pub fn build(self) -> crate::operation::describe_instance_types::DescribeInstanceTypesOutput {
        crate::operation::describe_instance_types::DescribeInstanceTypesOutput {
            instance_types: self.instance_types,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
