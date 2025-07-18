// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCatalogInput {
    /// <p>The name of the catalog to create.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A <code>CatalogInput</code> object that defines the metadata for the catalog.</p>
    pub catalog_input: ::std::option::Option<crate::types::CatalogInput>,
    /// <p>A map array of key-value pairs, not more than 50 pairs. Each key is a UTF-8 string, not less than 1 or more than 128 bytes long. Each value is a UTF-8 string, not more than 256 bytes long. The tags you assign to the catalog.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateCatalogInput {
    /// <p>The name of the catalog to create.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A <code>CatalogInput</code> object that defines the metadata for the catalog.</p>
    pub fn catalog_input(&self) -> ::std::option::Option<&crate::types::CatalogInput> {
        self.catalog_input.as_ref()
    }
    /// <p>A map array of key-value pairs, not more than 50 pairs. Each key is a UTF-8 string, not less than 1 or more than 128 bytes long. Each value is a UTF-8 string, not more than 256 bytes long. The tags you assign to the catalog.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateCatalogInput {
    /// Creates a new builder-style object to manufacture [`CreateCatalogInput`](crate::operation::create_catalog::CreateCatalogInput).
    pub fn builder() -> crate::operation::create_catalog::builders::CreateCatalogInputBuilder {
        crate::operation::create_catalog::builders::CreateCatalogInputBuilder::default()
    }
}

/// A builder for [`CreateCatalogInput`](crate::operation::create_catalog::CreateCatalogInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCatalogInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) catalog_input: ::std::option::Option<crate::types::CatalogInput>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateCatalogInputBuilder {
    /// <p>The name of the catalog to create.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the catalog to create.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the catalog to create.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A <code>CatalogInput</code> object that defines the metadata for the catalog.</p>
    /// This field is required.
    pub fn catalog_input(mut self, input: crate::types::CatalogInput) -> Self {
        self.catalog_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>CatalogInput</code> object that defines the metadata for the catalog.</p>
    pub fn set_catalog_input(mut self, input: ::std::option::Option<crate::types::CatalogInput>) -> Self {
        self.catalog_input = input;
        self
    }
    /// <p>A <code>CatalogInput</code> object that defines the metadata for the catalog.</p>
    pub fn get_catalog_input(&self) -> &::std::option::Option<crate::types::CatalogInput> {
        &self.catalog_input
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map array of key-value pairs, not more than 50 pairs. Each key is a UTF-8 string, not less than 1 or more than 128 bytes long. Each value is a UTF-8 string, not more than 256 bytes long. The tags you assign to the catalog.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map array of key-value pairs, not more than 50 pairs. Each key is a UTF-8 string, not less than 1 or more than 128 bytes long. Each value is a UTF-8 string, not more than 256 bytes long. The tags you assign to the catalog.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map array of key-value pairs, not more than 50 pairs. Each key is a UTF-8 string, not less than 1 or more than 128 bytes long. Each value is a UTF-8 string, not more than 256 bytes long. The tags you assign to the catalog.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateCatalogInput`](crate::operation::create_catalog::CreateCatalogInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_catalog::CreateCatalogInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_catalog::CreateCatalogInput {
            name: self.name,
            catalog_input: self.catalog_input,
            tags: self.tags,
        })
    }
}
