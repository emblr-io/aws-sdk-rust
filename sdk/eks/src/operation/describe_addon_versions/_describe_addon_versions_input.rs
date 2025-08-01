// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAddonVersionsInput {
    /// <p>The Kubernetes versions that you can use the add-on with.</p>
    pub kubernetes_version: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results, returned in paginated output. You receive <code>maxResults</code> in a single page, along with a <code>nextToken</code> response element. You can see the remaining results of the initial request by sending another request with the returned <code>nextToken</code> value. This value can be between 1 and 100. If you don't use this parameter, 100 results and a <code>nextToken</code> value, if applicable, are returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The <code>nextToken</code> value returned from a previous paginated request, where <code>maxResults</code> was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the <code>nextToken</code> value. This value is null when there are no more results to return.</p><note>
    /// <p>This token should be treated as an opaque identifier that is used only to retrieve the next items in a list and not for other programmatic purposes.</p>
    /// </note>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub addon_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of the add-on. For valid <code>types</code>, don't specify a value for this property.</p>
    pub types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The publisher of the add-on. For valid <code>publishers</code>, don't specify a value for this property.</p>
    pub publishers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The owner of the add-on. For valid <code>owners</code>, don't specify a value for this property.</p>
    pub owners: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeAddonVersionsInput {
    /// <p>The Kubernetes versions that you can use the add-on with.</p>
    pub fn kubernetes_version(&self) -> ::std::option::Option<&str> {
        self.kubernetes_version.as_deref()
    }
    /// <p>The maximum number of results, returned in paginated output. You receive <code>maxResults</code> in a single page, along with a <code>nextToken</code> response element. You can see the remaining results of the initial request by sending another request with the returned <code>nextToken</code> value. This value can be between 1 and 100. If you don't use this parameter, 100 results and a <code>nextToken</code> value, if applicable, are returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The <code>nextToken</code> value returned from a previous paginated request, where <code>maxResults</code> was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the <code>nextToken</code> value. This value is null when there are no more results to return.</p><note>
    /// <p>This token should be treated as an opaque identifier that is used only to retrieve the next items in a list and not for other programmatic purposes.</p>
    /// </note>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn addon_name(&self) -> ::std::option::Option<&str> {
        self.addon_name.as_deref()
    }
    /// <p>The type of the add-on. For valid <code>types</code>, don't specify a value for this property.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.types.is_none()`.
    pub fn types(&self) -> &[::std::string::String] {
        self.types.as_deref().unwrap_or_default()
    }
    /// <p>The publisher of the add-on. For valid <code>publishers</code>, don't specify a value for this property.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.publishers.is_none()`.
    pub fn publishers(&self) -> &[::std::string::String] {
        self.publishers.as_deref().unwrap_or_default()
    }
    /// <p>The owner of the add-on. For valid <code>owners</code>, don't specify a value for this property.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.owners.is_none()`.
    pub fn owners(&self) -> &[::std::string::String] {
        self.owners.as_deref().unwrap_or_default()
    }
}
impl DescribeAddonVersionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeAddonVersionsInput`](crate::operation::describe_addon_versions::DescribeAddonVersionsInput).
    pub fn builder() -> crate::operation::describe_addon_versions::builders::DescribeAddonVersionsInputBuilder {
        crate::operation::describe_addon_versions::builders::DescribeAddonVersionsInputBuilder::default()
    }
}

/// A builder for [`DescribeAddonVersionsInput`](crate::operation::describe_addon_versions::DescribeAddonVersionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAddonVersionsInputBuilder {
    pub(crate) kubernetes_version: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) addon_name: ::std::option::Option<::std::string::String>,
    pub(crate) types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) publishers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) owners: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeAddonVersionsInputBuilder {
    /// <p>The Kubernetes versions that you can use the add-on with.</p>
    pub fn kubernetes_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kubernetes_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Kubernetes versions that you can use the add-on with.</p>
    pub fn set_kubernetes_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kubernetes_version = input;
        self
    }
    /// <p>The Kubernetes versions that you can use the add-on with.</p>
    pub fn get_kubernetes_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.kubernetes_version
    }
    /// <p>The maximum number of results, returned in paginated output. You receive <code>maxResults</code> in a single page, along with a <code>nextToken</code> response element. You can see the remaining results of the initial request by sending another request with the returned <code>nextToken</code> value. This value can be between 1 and 100. If you don't use this parameter, 100 results and a <code>nextToken</code> value, if applicable, are returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results, returned in paginated output. You receive <code>maxResults</code> in a single page, along with a <code>nextToken</code> response element. You can see the remaining results of the initial request by sending another request with the returned <code>nextToken</code> value. This value can be between 1 and 100. If you don't use this parameter, 100 results and a <code>nextToken</code> value, if applicable, are returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results, returned in paginated output. You receive <code>maxResults</code> in a single page, along with a <code>nextToken</code> response element. You can see the remaining results of the initial request by sending another request with the returned <code>nextToken</code> value. This value can be between 1 and 100. If you don't use this parameter, 100 results and a <code>nextToken</code> value, if applicable, are returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The <code>nextToken</code> value returned from a previous paginated request, where <code>maxResults</code> was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the <code>nextToken</code> value. This value is null when there are no more results to return.</p><note>
    /// <p>This token should be treated as an opaque identifier that is used only to retrieve the next items in a list and not for other programmatic purposes.</p>
    /// </note>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> value returned from a previous paginated request, where <code>maxResults</code> was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the <code>nextToken</code> value. This value is null when there are no more results to return.</p><note>
    /// <p>This token should be treated as an opaque identifier that is used only to retrieve the next items in a list and not for other programmatic purposes.</p>
    /// </note>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> value returned from a previous paginated request, where <code>maxResults</code> was used and the results exceeded the value of that parameter. Pagination continues from the end of the previous results that returned the <code>nextToken</code> value. This value is null when there are no more results to return.</p><note>
    /// <p>This token should be treated as an opaque identifier that is used only to retrieve the next items in a list and not for other programmatic purposes.</p>
    /// </note>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn addon_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn set_addon_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_name = input;
        self
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn get_addon_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_name
    }
    /// Appends an item to `types`.
    ///
    /// To override the contents of this collection use [`set_types`](Self::set_types).
    ///
    /// <p>The type of the add-on. For valid <code>types</code>, don't specify a value for this property.</p>
    pub fn types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.types.unwrap_or_default();
        v.push(input.into());
        self.types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The type of the add-on. For valid <code>types</code>, don't specify a value for this property.</p>
    pub fn set_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.types = input;
        self
    }
    /// <p>The type of the add-on. For valid <code>types</code>, don't specify a value for this property.</p>
    pub fn get_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.types
    }
    /// Appends an item to `publishers`.
    ///
    /// To override the contents of this collection use [`set_publishers`](Self::set_publishers).
    ///
    /// <p>The publisher of the add-on. For valid <code>publishers</code>, don't specify a value for this property.</p>
    pub fn publishers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.publishers.unwrap_or_default();
        v.push(input.into());
        self.publishers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The publisher of the add-on. For valid <code>publishers</code>, don't specify a value for this property.</p>
    pub fn set_publishers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.publishers = input;
        self
    }
    /// <p>The publisher of the add-on. For valid <code>publishers</code>, don't specify a value for this property.</p>
    pub fn get_publishers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.publishers
    }
    /// Appends an item to `owners`.
    ///
    /// To override the contents of this collection use [`set_owners`](Self::set_owners).
    ///
    /// <p>The owner of the add-on. For valid <code>owners</code>, don't specify a value for this property.</p>
    pub fn owners(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.owners.unwrap_or_default();
        v.push(input.into());
        self.owners = ::std::option::Option::Some(v);
        self
    }
    /// <p>The owner of the add-on. For valid <code>owners</code>, don't specify a value for this property.</p>
    pub fn set_owners(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.owners = input;
        self
    }
    /// <p>The owner of the add-on. For valid <code>owners</code>, don't specify a value for this property.</p>
    pub fn get_owners(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.owners
    }
    /// Consumes the builder and constructs a [`DescribeAddonVersionsInput`](crate::operation::describe_addon_versions::DescribeAddonVersionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_addon_versions::DescribeAddonVersionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_addon_versions::DescribeAddonVersionsInput {
            kubernetes_version: self.kubernetes_version,
            max_results: self.max_results,
            next_token: self.next_token,
            addon_name: self.addon_name,
            types: self.types,
            publishers: self.publishers,
            owners: self.owners,
        })
    }
}
