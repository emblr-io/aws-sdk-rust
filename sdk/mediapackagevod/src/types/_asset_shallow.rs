// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// A MediaPackage VOD Asset resource.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetShallow {
    /// The ARN of the Asset.
    pub arn: ::std::option::Option<::std::string::String>,
    /// The time the Asset was initially submitted for Ingest.
    pub created_at: ::std::option::Option<::std::string::String>,
    /// The unique identifier for the Asset.
    pub id: ::std::option::Option<::std::string::String>,
    /// The ID of the PackagingGroup for the Asset.
    pub packaging_group_id: ::std::option::Option<::std::string::String>,
    /// The resource ID to include in SPEKE key requests.
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// ARN of the source object in S3.
    pub source_arn: ::std::option::Option<::std::string::String>,
    /// The IAM role ARN used to access the source S3 bucket.
    pub source_role_arn: ::std::option::Option<::std::string::String>,
    /// A collection of tags associated with a resource
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AssetShallow {
    /// The ARN of the Asset.
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// The time the Asset was initially submitted for Ingest.
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
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
    /// The IAM role ARN used to access the source S3 bucket.
    pub fn source_role_arn(&self) -> ::std::option::Option<&str> {
        self.source_role_arn.as_deref()
    }
    /// A collection of tags associated with a resource
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl AssetShallow {
    /// Creates a new builder-style object to manufacture [`AssetShallow`](crate::types::AssetShallow).
    pub fn builder() -> crate::types::builders::AssetShallowBuilder {
        crate::types::builders::AssetShallowBuilder::default()
    }
}

/// A builder for [`AssetShallow`](crate::types::AssetShallow).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetShallowBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) packaging_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AssetShallowBuilder {
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
    /// The IAM role ARN used to access the source S3 bucket.
    pub fn source_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The IAM role ARN used to access the source S3 bucket.
    pub fn set_source_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_role_arn = input;
        self
    }
    /// The IAM role ARN used to access the source S3 bucket.
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
    /// Consumes the builder and constructs a [`AssetShallow`](crate::types::AssetShallow).
    pub fn build(self) -> crate::types::AssetShallow {
        crate::types::AssetShallow {
            arn: self.arn,
            created_at: self.created_at,
            id: self.id,
            packaging_group_id: self.packaging_group_id,
            resource_id: self.resource_id,
            source_arn: self.source_arn,
            source_role_arn: self.source_role_arn,
            tags: self.tags,
        }
    }
}
