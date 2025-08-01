// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchProvisionedProductsInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>The access level to use to obtain results. The default is <code>Account</code>.</p>
    pub access_level_filter: ::std::option::Option<crate::types::AccessLevelFilter>,
    /// <p>The search filters.</p>
    /// <p>When the key is <code>SearchQuery</code>, the searchable fields are <code>arn</code>, <code>createdTime</code>, <code>id</code>, <code>lastRecordId</code>, <code>idempotencyToken</code>, <code>name</code>, <code>physicalId</code>, <code>productId</code>, <code>provisioningArtifactId</code>, <code>type</code>, <code>status</code>, <code>tags</code>, <code>userArn</code>, <code>userArnSession</code>, <code>lastProvisioningRecordId</code>, <code>lastSuccessfulProvisioningRecordId</code>, <code>productName</code>, and <code>provisioningArtifactName</code>.</p>
    /// <p>Example: <code>"SearchQuery":\["status:AVAILABLE"\]</code></p>
    pub filters:
        ::std::option::Option<::std::collections::HashMap<crate::types::ProvisionedProductViewFilterBy, ::std::vec::Vec<::std::string::String>>>,
    /// <p>The sort field. If no value is specified, the results are not sorted. The valid values are <code>arn</code>, <code>id</code>, <code>name</code>, and <code>lastRecordId</code>.</p>
    pub sort_by: ::std::option::Option<::std::string::String>,
    /// <p>The sort order. If no value is specified, the results are not sorted.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>The maximum number of items to return with this call.</p>
    pub page_size: ::std::option::Option<i32>,
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub page_token: ::std::option::Option<::std::string::String>,
}
impl SearchProvisionedProductsInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(&self) -> ::std::option::Option<&str> {
        self.accept_language.as_deref()
    }
    /// <p>The access level to use to obtain results. The default is <code>Account</code>.</p>
    pub fn access_level_filter(&self) -> ::std::option::Option<&crate::types::AccessLevelFilter> {
        self.access_level_filter.as_ref()
    }
    /// <p>The search filters.</p>
    /// <p>When the key is <code>SearchQuery</code>, the searchable fields are <code>arn</code>, <code>createdTime</code>, <code>id</code>, <code>lastRecordId</code>, <code>idempotencyToken</code>, <code>name</code>, <code>physicalId</code>, <code>productId</code>, <code>provisioningArtifactId</code>, <code>type</code>, <code>status</code>, <code>tags</code>, <code>userArn</code>, <code>userArnSession</code>, <code>lastProvisioningRecordId</code>, <code>lastSuccessfulProvisioningRecordId</code>, <code>productName</code>, and <code>provisioningArtifactName</code>.</p>
    /// <p>Example: <code>"SearchQuery":\["status:AVAILABLE"\]</code></p>
    pub fn filters(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<crate::types::ProvisionedProductViewFilterBy, ::std::vec::Vec<::std::string::String>>>
    {
        self.filters.as_ref()
    }
    /// <p>The sort field. If no value is specified, the results are not sorted. The valid values are <code>arn</code>, <code>id</code>, <code>name</code>, and <code>lastRecordId</code>.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&str> {
        self.sort_by.as_deref()
    }
    /// <p>The sort order. If no value is specified, the results are not sorted.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn page_token(&self) -> ::std::option::Option<&str> {
        self.page_token.as_deref()
    }
}
impl SearchProvisionedProductsInput {
    /// Creates a new builder-style object to manufacture [`SearchProvisionedProductsInput`](crate::operation::search_provisioned_products::SearchProvisionedProductsInput).
    pub fn builder() -> crate::operation::search_provisioned_products::builders::SearchProvisionedProductsInputBuilder {
        crate::operation::search_provisioned_products::builders::SearchProvisionedProductsInputBuilder::default()
    }
}

/// A builder for [`SearchProvisionedProductsInput`](crate::operation::search_provisioned_products::SearchProvisionedProductsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchProvisionedProductsInputBuilder {
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) access_level_filter: ::std::option::Option<crate::types::AccessLevelFilter>,
    pub(crate) filters:
        ::std::option::Option<::std::collections::HashMap<crate::types::ProvisionedProductViewFilterBy, ::std::vec::Vec<::std::string::String>>>,
    pub(crate) sort_by: ::std::option::Option<::std::string::String>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) page_size: ::std::option::Option<i32>,
    pub(crate) page_token: ::std::option::Option<::std::string::String>,
}
impl SearchProvisionedProductsInputBuilder {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn set_accept_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn get_accept_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept_language
    }
    /// <p>The access level to use to obtain results. The default is <code>Account</code>.</p>
    pub fn access_level_filter(mut self, input: crate::types::AccessLevelFilter) -> Self {
        self.access_level_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The access level to use to obtain results. The default is <code>Account</code>.</p>
    pub fn set_access_level_filter(mut self, input: ::std::option::Option<crate::types::AccessLevelFilter>) -> Self {
        self.access_level_filter = input;
        self
    }
    /// <p>The access level to use to obtain results. The default is <code>Account</code>.</p>
    pub fn get_access_level_filter(&self) -> &::std::option::Option<crate::types::AccessLevelFilter> {
        &self.access_level_filter
    }
    /// Adds a key-value pair to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>The search filters.</p>
    /// <p>When the key is <code>SearchQuery</code>, the searchable fields are <code>arn</code>, <code>createdTime</code>, <code>id</code>, <code>lastRecordId</code>, <code>idempotencyToken</code>, <code>name</code>, <code>physicalId</code>, <code>productId</code>, <code>provisioningArtifactId</code>, <code>type</code>, <code>status</code>, <code>tags</code>, <code>userArn</code>, <code>userArnSession</code>, <code>lastProvisioningRecordId</code>, <code>lastSuccessfulProvisioningRecordId</code>, <code>productName</code>, and <code>provisioningArtifactName</code>.</p>
    /// <p>Example: <code>"SearchQuery":\["status:AVAILABLE"\]</code></p>
    pub fn filters(mut self, k: crate::types::ProvisionedProductViewFilterBy, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.filters.unwrap_or_default();
        hash_map.insert(k, v);
        self.filters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The search filters.</p>
    /// <p>When the key is <code>SearchQuery</code>, the searchable fields are <code>arn</code>, <code>createdTime</code>, <code>id</code>, <code>lastRecordId</code>, <code>idempotencyToken</code>, <code>name</code>, <code>physicalId</code>, <code>productId</code>, <code>provisioningArtifactId</code>, <code>type</code>, <code>status</code>, <code>tags</code>, <code>userArn</code>, <code>userArnSession</code>, <code>lastProvisioningRecordId</code>, <code>lastSuccessfulProvisioningRecordId</code>, <code>productName</code>, and <code>provisioningArtifactName</code>.</p>
    /// <p>Example: <code>"SearchQuery":\["status:AVAILABLE"\]</code></p>
    pub fn set_filters(
        mut self,
        input: ::std::option::Option<
            ::std::collections::HashMap<crate::types::ProvisionedProductViewFilterBy, ::std::vec::Vec<::std::string::String>>,
        >,
    ) -> Self {
        self.filters = input;
        self
    }
    /// <p>The search filters.</p>
    /// <p>When the key is <code>SearchQuery</code>, the searchable fields are <code>arn</code>, <code>createdTime</code>, <code>id</code>, <code>lastRecordId</code>, <code>idempotencyToken</code>, <code>name</code>, <code>physicalId</code>, <code>productId</code>, <code>provisioningArtifactId</code>, <code>type</code>, <code>status</code>, <code>tags</code>, <code>userArn</code>, <code>userArnSession</code>, <code>lastProvisioningRecordId</code>, <code>lastSuccessfulProvisioningRecordId</code>, <code>productName</code>, and <code>provisioningArtifactName</code>.</p>
    /// <p>Example: <code>"SearchQuery":\["status:AVAILABLE"\]</code></p>
    pub fn get_filters(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<crate::types::ProvisionedProductViewFilterBy, ::std::vec::Vec<::std::string::String>>>
    {
        &self.filters
    }
    /// <p>The sort field. If no value is specified, the results are not sorted. The valid values are <code>arn</code>, <code>id</code>, <code>name</code>, and <code>lastRecordId</code>.</p>
    pub fn sort_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sort_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The sort field. If no value is specified, the results are not sorted. The valid values are <code>arn</code>, <code>id</code>, <code>name</code>, and <code>lastRecordId</code>.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The sort field. If no value is specified, the results are not sorted. The valid values are <code>arn</code>, <code>id</code>, <code>name</code>, and <code>lastRecordId</code>.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.sort_by
    }
    /// <p>The sort order. If no value is specified, the results are not sorted.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort order. If no value is specified, the results are not sorted.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The sort order. If no value is specified, the results are not sorted.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn set_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.page_token = input;
        self
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn get_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.page_token
    }
    /// Consumes the builder and constructs a [`SearchProvisionedProductsInput`](crate::operation::search_provisioned_products::SearchProvisionedProductsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::search_provisioned_products::SearchProvisionedProductsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::search_provisioned_products::SearchProvisionedProductsInput {
            accept_language: self.accept_language,
            access_level_filter: self.access_level_filter,
            filters: self.filters,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            page_size: self.page_size,
            page_token: self.page_token,
        })
    }
}
