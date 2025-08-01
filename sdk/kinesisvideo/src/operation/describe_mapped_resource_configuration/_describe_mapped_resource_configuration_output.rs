// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMappedResourceConfigurationOutput {
    /// <p>A structure that encapsulates, or contains, the media storage configuration properties.</p>
    pub mapped_resource_configuration_list: ::std::option::Option<::std::vec::Vec<crate::types::MappedResourceConfigurationListItem>>,
    /// <p>The token that was used in the <code>NextToken</code>request to fetch the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeMappedResourceConfigurationOutput {
    /// <p>A structure that encapsulates, or contains, the media storage configuration properties.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.mapped_resource_configuration_list.is_none()`.
    pub fn mapped_resource_configuration_list(&self) -> &[crate::types::MappedResourceConfigurationListItem] {
        self.mapped_resource_configuration_list.as_deref().unwrap_or_default()
    }
    /// <p>The token that was used in the <code>NextToken</code>request to fetch the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeMappedResourceConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeMappedResourceConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeMappedResourceConfigurationOutput`](crate::operation::describe_mapped_resource_configuration::DescribeMappedResourceConfigurationOutput).
    pub fn builder() -> crate::operation::describe_mapped_resource_configuration::builders::DescribeMappedResourceConfigurationOutputBuilder {
        crate::operation::describe_mapped_resource_configuration::builders::DescribeMappedResourceConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeMappedResourceConfigurationOutput`](crate::operation::describe_mapped_resource_configuration::DescribeMappedResourceConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMappedResourceConfigurationOutputBuilder {
    pub(crate) mapped_resource_configuration_list: ::std::option::Option<::std::vec::Vec<crate::types::MappedResourceConfigurationListItem>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeMappedResourceConfigurationOutputBuilder {
    /// Appends an item to `mapped_resource_configuration_list`.
    ///
    /// To override the contents of this collection use [`set_mapped_resource_configuration_list`](Self::set_mapped_resource_configuration_list).
    ///
    /// <p>A structure that encapsulates, or contains, the media storage configuration properties.</p>
    pub fn mapped_resource_configuration_list(mut self, input: crate::types::MappedResourceConfigurationListItem) -> Self {
        let mut v = self.mapped_resource_configuration_list.unwrap_or_default();
        v.push(input);
        self.mapped_resource_configuration_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A structure that encapsulates, or contains, the media storage configuration properties.</p>
    pub fn set_mapped_resource_configuration_list(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::MappedResourceConfigurationListItem>>,
    ) -> Self {
        self.mapped_resource_configuration_list = input;
        self
    }
    /// <p>A structure that encapsulates, or contains, the media storage configuration properties.</p>
    pub fn get_mapped_resource_configuration_list(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::MappedResourceConfigurationListItem>> {
        &self.mapped_resource_configuration_list
    }
    /// <p>The token that was used in the <code>NextToken</code>request to fetch the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that was used in the <code>NextToken</code>request to fetch the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that was used in the <code>NextToken</code>request to fetch the next set of results.</p>
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
    /// Consumes the builder and constructs a [`DescribeMappedResourceConfigurationOutput`](crate::operation::describe_mapped_resource_configuration::DescribeMappedResourceConfigurationOutput).
    pub fn build(self) -> crate::operation::describe_mapped_resource_configuration::DescribeMappedResourceConfigurationOutput {
        crate::operation::describe_mapped_resource_configuration::DescribeMappedResourceConfigurationOutput {
            mapped_resource_configuration_list: self.mapped_resource_configuration_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
