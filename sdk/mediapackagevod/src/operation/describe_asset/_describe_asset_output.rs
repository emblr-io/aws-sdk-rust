// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAssetOutput {
    /// The ARN of the Asset.
    pub arn: ::std::option::Option<::std::string::String>,
    /// The time the Asset was initially submitted for Ingest.
    pub created_at: ::std::option::Option<::std::string::String>,
    /// The list of egress endpoints available for the Asset.
    pub egress_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::EgressEndpoint>>,
    /// The unique identifier for the Asset.
    pub id: ::std::option::Option<::std::string::String>,
    /// The ID of the PackagingGroup for the Asset.
    pub packaging_group_id: ::std::option::Option<::std::string::String>,
    /// The resource ID to include in SPEKE key requests.
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// ARN of the source object in S3.
    pub source_arn: ::std::option::Option<::std::string::String>,
    /// The IAM role_arn used to access the source S3 bucket.
    pub source_role_arn: ::std::option::Option<::std::string::String>,
    /// A collection of tags associated with a resource
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeAssetOutput {
    /// The ARN of the Asset.
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// The time the Asset was initially submitted for Ingest.
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
    }
    /// The list of egress endpoints available for the Asset.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.egress_endpoints.is_none()`.
    pub fn egress_endpoints(&self) -> &[crate::types::EgressEndpoint] {
        self.egress_endpoints.as_deref().unwrap_or_default()
    }
    /// The unique identifier for the Asset.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// The ID of the PackagingGroup for the Asset.
    pub fn packaging_group_id(&self) -> ::std::option::Option<&str> {
        self.packaging_group_id.as_deref()
    }
    /// The resource ID to include in SPEKE key requests.
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// ARN of the source object in S3.
    pub fn source_arn(&self) -> ::std::option::Option<&str> {
        self.source_arn.as_deref()
    }
    /// The IAM role_arn used to access the source S3 bucket.
    pub fn source_role_arn(&self) -> ::std::option::Option<&str> {
        self.source_role_arn.as_deref()
    }
    /// A collection of tags associated with a resource
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeAssetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAssetOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAssetOutput`](crate::operation::describe_asset::DescribeAssetOutput).
    pub fn builder() -> crate::operation::describe_asset::builders::DescribeAssetOutputBuilder {
        crate::operation::describe_asset::builders::DescribeAssetOutputBuilder::default()
    }
}

/// A builder for [`DescribeAssetOutput`](crate::operation::describe_asset::DescribeAssetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAssetOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) egress_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::EgressEndpoint>>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) packaging_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeAssetOutputBuilder {
    /// The ARN of the Asset.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The ARN of the Asset.
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// The ARN of the Asset.
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// The time the Asset was initially submitted for Ingest.
    pub fn created_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_at = ::std::option::Option::Some(input.into());
        self
    }
    /// The time the Asset was initially submitted for Ingest.
    pub fn set_created_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_at = input;
        self
    }
    /// The time the Asset was initially submitted for Ingest.
    pub fn get_created_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_at
    }
    /// Appends an item to `egress_endpoints`.
    ///
    /// To override the contents of this collection use [`set_egress_endpoints`](Self::set_egress_endpoints).
    ///
    /// The list of egress endpoints available for the Asset.
    pub fn egress_endpoints(mut self, input: crate::types::EgressEndpoint) -> Self {
        let mut v = self.egress_endpoints.unwrap_or_default();
        v.push(input);
        self.egress_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// The list of egress endpoints available for the Asset.
    pub fn set_egress_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EgressEndpoint>>) -> Self {
        self.egress_endpoints = input;
        self
    }
    /// The list of egress endpoints available for the Asset.
    pub fn get_egress_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EgressEndpoint>> {
        &self.egress_endpoints
    }
    /// The unique identifier for the Asset.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique identifier for the Asset.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The unique identifier for the Asset.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// The ID of the PackagingGroup for the Asset.
    pub fn packaging_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.packaging_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the PackagingGroup for the Asset.
    pub fn set_packaging_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.packaging_group_id = input;
        self
    }
    /// The ID of the PackagingGroup for the Asset.
    pub fn get_packaging_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.packaging_group_id
    }
    /// The resource ID to include in SPEKE key requests.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The resource ID to include in SPEKE key requests.
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// The resource ID to include in SPEKE key requests.
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// ARN of the source object in S3.
    pub fn source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// ARN of the source object in S3.
    pub fn set_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_arn = input;
        self
    }
    /// ARN of the source object in S3.
    pub fn get_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_arn
    }
    /// The IAM role_arn used to access the source S3 bucket.
    pub fn source_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The IAM role_arn used to access the source S3 bucket.
    pub fn set_source_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_role_arn = input;
        self
    }
    /// The IAM role_arn used to access the source S3 bucket.
    pub fn get_source_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_role_arn
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// A collection of tags associated with a resource
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// A collection of tags associated with a resource
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// A collection of tags associated with a resource
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeAssetOutput`](crate::operation::describe_asset::DescribeAssetOutput).
    pub fn build(self) -> crate::operation::describe_asset::DescribeAssetOutput {
        crate::operation::describe_asset::DescribeAssetOutput {
            arn: self.arn,
            created_at: self.created_at,
            egress_endpoints: self.egress_endpoints,
            id: self.id,
            packaging_group_id: self.packaging_group_id,
            resource_id: self.resource_id,
            source_arn: self.source_arn,
            source_role_arn: self.source_role_arn,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
