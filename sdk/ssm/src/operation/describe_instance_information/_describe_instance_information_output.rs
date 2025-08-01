// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInstanceInformationOutput {
    /// <p>The managed node information list.</p>
    pub instance_information_list: ::std::option::Option<::std::vec::Vec<crate::types::InstanceInformation>>,
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeInstanceInformationOutput {
    /// <p>The managed node information list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_information_list.is_none()`.
    pub fn instance_information_list(&self) -> &[crate::types::InstanceInformation] {
        self.instance_information_list.as_deref().unwrap_or_default()
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeInstanceInformationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeInstanceInformationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeInstanceInformationOutput`](crate::operation::describe_instance_information::DescribeInstanceInformationOutput).
    pub fn builder() -> crate::operation::describe_instance_information::builders::DescribeInstanceInformationOutputBuilder {
        crate::operation::describe_instance_information::builders::DescribeInstanceInformationOutputBuilder::default()
    }
}

/// A builder for [`DescribeInstanceInformationOutput`](crate::operation::describe_instance_information::DescribeInstanceInformationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInstanceInformationOutputBuilder {
    pub(crate) instance_information_list: ::std::option::Option<::std::vec::Vec<crate::types::InstanceInformation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeInstanceInformationOutputBuilder {
    /// Appends an item to `instance_information_list`.
    ///
    /// To override the contents of this collection use [`set_instance_information_list`](Self::set_instance_information_list).
    ///
    /// <p>The managed node information list.</p>
    pub fn instance_information_list(mut self, input: crate::types::InstanceInformation) -> Self {
        let mut v = self.instance_information_list.unwrap_or_default();
        v.push(input);
        self.instance_information_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The managed node information list.</p>
    pub fn set_instance_information_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstanceInformation>>) -> Self {
        self.instance_information_list = input;
        self
    }
    /// <p>The managed node information list.</p>
    pub fn get_instance_information_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstanceInformation>> {
        &self.instance_information_list
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
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
    /// Consumes the builder and constructs a [`DescribeInstanceInformationOutput`](crate::operation::describe_instance_information::DescribeInstanceInformationOutput).
    pub fn build(self) -> crate::operation::describe_instance_information::DescribeInstanceInformationOutput {
        crate::operation::describe_instance_information::DescribeInstanceInformationOutput {
            instance_information_list: self.instance_information_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
