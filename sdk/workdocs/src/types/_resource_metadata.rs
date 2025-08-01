// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the metadata of a resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ResourceMetadata {
    /// <p>The type of resource.</p>
    pub r#type: ::std::option::Option<crate::types::ResourceType>,
    /// <p>The name of the resource.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The original name of the resource before a rename operation.</p>
    pub original_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the resource.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The version ID of the resource. This is an optional field and is filled for action on document version.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the resource.</p>
    pub owner: ::std::option::Option<crate::types::UserMetadata>,
    /// <p>The parent ID of the resource before a rename operation.</p>
    pub parent_id: ::std::option::Option<::std::string::String>,
}
impl ResourceMetadata {
    /// <p>The type of resource.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.r#type.as_ref()
    }
    /// <p>The name of the resource.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The original name of the resource before a rename operation.</p>
    pub fn original_name(&self) -> ::std::option::Option<&str> {
        self.original_name.as_deref()
    }
    /// <p>The ID of the resource.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The version ID of the resource. This is an optional field and is filled for action on document version.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>The owner of the resource.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::UserMetadata> {
        self.owner.as_ref()
    }
    /// <p>The parent ID of the resource before a rename operation.</p>
    pub fn parent_id(&self) -> ::std::option::Option<&str> {
        self.parent_id.as_deref()
    }
}
impl ::std::fmt::Debug for ResourceMetadata {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ResourceMetadata");
        formatter.field("r#type", &self.r#type);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("original_name", &"*** Sensitive Data Redacted ***");
        formatter.field("id", &self.id);
        formatter.field("version_id", &self.version_id);
        formatter.field("owner", &self.owner);
        formatter.field("parent_id", &self.parent_id);
        formatter.finish()
    }
}
impl ResourceMetadata {
    /// Creates a new builder-style object to manufacture [`ResourceMetadata`](crate::types::ResourceMetadata).
    pub fn builder() -> crate::types::builders::ResourceMetadataBuilder {
        crate::types::builders::ResourceMetadataBuilder::default()
    }
}

/// A builder for [`ResourceMetadata`](crate::types::ResourceMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ResourceMetadataBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) original_name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<crate::types::UserMetadata>,
    pub(crate) parent_id: ::std::option::Option<::std::string::String>,
}
impl ResourceMetadataBuilder {
    /// <p>The type of resource.</p>
    pub fn r#type(mut self, input: crate::types::ResourceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of resource.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.r#type
    }
    /// <p>The name of the resource.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the resource.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The original name of the resource before a rename operation.</p>
    pub fn original_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.original_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The original name of the resource before a rename operation.</p>
    pub fn set_original_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.original_name = input;
        self
    }
    /// <p>The original name of the resource before a rename operation.</p>
    pub fn get_original_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.original_name
    }
    /// <p>The ID of the resource.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The version ID of the resource. This is an optional field and is filled for action on document version.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version ID of the resource. This is an optional field and is filled for action on document version.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The version ID of the resource. This is an optional field and is filled for action on document version.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// <p>The owner of the resource.</p>
    pub fn owner(mut self, input: crate::types::UserMetadata) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>The owner of the resource.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::UserMetadata>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the resource.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::UserMetadata> {
        &self.owner
    }
    /// <p>The parent ID of the resource before a rename operation.</p>
    pub fn parent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parent ID of the resource before a rename operation.</p>
    pub fn set_parent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_id = input;
        self
    }
    /// <p>The parent ID of the resource before a rename operation.</p>
    pub fn get_parent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_id
    }
    /// Consumes the builder and constructs a [`ResourceMetadata`](crate::types::ResourceMetadata).
    pub fn build(self) -> crate::types::ResourceMetadata {
        crate::types::ResourceMetadata {
            r#type: self.r#type,
            name: self.name,
            original_name: self.original_name,
            id: self.id,
            version_id: self.version_id,
            owner: self.owner,
            parent_id: self.parent_id,
        }
    }
}
impl ::std::fmt::Debug for ResourceMetadataBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ResourceMetadataBuilder");
        formatter.field("r#type", &self.r#type);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("original_name", &"*** Sensitive Data Redacted ***");
        formatter.field("id", &self.id);
        formatter.field("version_id", &self.version_id);
        formatter.field("owner", &self.owner);
        formatter.field("parent_id", &self.parent_id);
        formatter.finish()
    }
}
