// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPermissionsInput {
    /// <p>The identifier for the Data Catalog. By default, the account ID. The Data Catalog is the persistent metadata store. It contains database definitions, table definitions, and other control information to manage your Lake Formation environment.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a principal to filter the permissions returned.</p>
    pub principal: ::std::option::Option<crate::types::DataLakePrincipal>,
    /// <p>Specifies a resource type to filter the permissions returned.</p>
    pub resource_type: ::std::option::Option<crate::types::DataLakeResourceType>,
    /// <p>A resource where you will get a list of the principal permissions.</p>
    /// <p>This operation does not support getting privileges on a table with columns. Instead, call this operation on the table, and the operation returns the table and the table w columns.</p>
    pub resource: ::std::option::Option<crate::types::Resource>,
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Indicates that related permissions should be included in the results.</p>
    pub include_related: ::std::option::Option<::std::string::String>,
}
impl ListPermissionsInput {
    /// <p>The identifier for the Data Catalog. By default, the account ID. The Data Catalog is the persistent metadata store. It contains database definitions, table definitions, and other control information to manage your Lake Formation environment.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>Specifies a principal to filter the permissions returned.</p>
    pub fn principal(&self) -> ::std::option::Option<&crate::types::DataLakePrincipal> {
        self.principal.as_ref()
    }
    /// <p>Specifies a resource type to filter the permissions returned.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::DataLakeResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>A resource where you will get a list of the principal permissions.</p>
    /// <p>This operation does not support getting privileges on a table with columns. Instead, call this operation on the table, and the operation returns the table and the table w columns.</p>
    pub fn resource(&self) -> ::std::option::Option<&crate::types::Resource> {
        self.resource.as_ref()
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Indicates that related permissions should be included in the results.</p>
    pub fn include_related(&self) -> ::std::option::Option<&str> {
        self.include_related.as_deref()
    }
}
impl ListPermissionsInput {
    /// Creates a new builder-style object to manufacture [`ListPermissionsInput`](crate::operation::list_permissions::ListPermissionsInput).
    pub fn builder() -> crate::operation::list_permissions::builders::ListPermissionsInputBuilder {
        crate::operation::list_permissions::builders::ListPermissionsInputBuilder::default()
    }
}

/// A builder for [`ListPermissionsInput`](crate::operation::list_permissions::ListPermissionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPermissionsInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal: ::std::option::Option<crate::types::DataLakePrincipal>,
    pub(crate) resource_type: ::std::option::Option<crate::types::DataLakeResourceType>,
    pub(crate) resource: ::std::option::Option<crate::types::Resource>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) include_related: ::std::option::Option<::std::string::String>,
}
impl ListPermissionsInputBuilder {
    /// <p>The identifier for the Data Catalog. By default, the account ID. The Data Catalog is the persistent metadata store. It contains database definitions, table definitions, and other control information to manage your Lake Formation environment.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the Data Catalog. By default, the account ID. The Data Catalog is the persistent metadata store. It contains database definitions, table definitions, and other control information to manage your Lake Formation environment.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The identifier for the Data Catalog. By default, the account ID. The Data Catalog is the persistent metadata store. It contains database definitions, table definitions, and other control information to manage your Lake Formation environment.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>Specifies a principal to filter the permissions returned.</p>
    pub fn principal(mut self, input: crate::types::DataLakePrincipal) -> Self {
        self.principal = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a principal to filter the permissions returned.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<crate::types::DataLakePrincipal>) -> Self {
        self.principal = input;
        self
    }
    /// <p>Specifies a principal to filter the permissions returned.</p>
    pub fn get_principal(&self) -> &::std::option::Option<crate::types::DataLakePrincipal> {
        &self.principal
    }
    /// <p>Specifies a resource type to filter the permissions returned.</p>
    pub fn resource_type(mut self, input: crate::types::DataLakeResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a resource type to filter the permissions returned.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::DataLakeResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>Specifies a resource type to filter the permissions returned.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::DataLakeResourceType> {
        &self.resource_type
    }
    /// <p>A resource where you will get a list of the principal permissions.</p>
    /// <p>This operation does not support getting privileges on a table with columns. Instead, call this operation on the table, and the operation returns the table and the table w columns.</p>
    pub fn resource(mut self, input: crate::types::Resource) -> Self {
        self.resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>A resource where you will get a list of the principal permissions.</p>
    /// <p>This operation does not support getting privileges on a table with columns. Instead, call this operation on the table, and the operation returns the table and the table w columns.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<crate::types::Resource>) -> Self {
        self.resource = input;
        self
    }
    /// <p>A resource where you will get a list of the principal permissions.</p>
    /// <p>This operation does not support getting privileges on a table with columns. Instead, call this operation on the table, and the operation returns the table and the table w columns.</p>
    pub fn get_resource(&self) -> &::std::option::Option<crate::types::Resource> {
        &self.resource
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Indicates that related permissions should be included in the results.</p>
    pub fn include_related(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.include_related = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates that related permissions should be included in the results.</p>
    pub fn set_include_related(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.include_related = input;
        self
    }
    /// <p>Indicates that related permissions should be included in the results.</p>
    pub fn get_include_related(&self) -> &::std::option::Option<::std::string::String> {
        &self.include_related
    }
    /// Consumes the builder and constructs a [`ListPermissionsInput`](crate::operation::list_permissions::ListPermissionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_permissions::ListPermissionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_permissions::ListPermissionsInput {
            catalog_id: self.catalog_id,
            principal: self.principal,
            resource_type: self.resource_type,
            resource: self.resource,
            next_token: self.next_token,
            max_results: self.max_results,
            include_related: self.include_related,
        })
    }
}
