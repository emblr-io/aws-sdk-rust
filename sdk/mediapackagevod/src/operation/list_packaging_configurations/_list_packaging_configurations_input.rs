// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPackagingConfigurationsInput {
    /// Upper bound on number of records to return.
    pub max_results: ::std::option::Option<i32>,
    /// A token used to resume pagination from the end of a previous request.
    pub next_token: ::std::option::Option<::std::string::String>,
    /// Returns MediaPackage VOD PackagingConfigurations associated with the specified PackagingGroup.
    pub packaging_group_id: ::std::option::Option<::std::string::String>,
}
impl ListPackagingConfigurationsInput {
    /// Upper bound on number of records to return.
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// A token used to resume pagination from the end of a previous request.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// Returns MediaPackage VOD PackagingConfigurations associated with the specified PackagingGroup.
    pub fn packaging_group_id(&self) -> ::std::option::Option<&str> {
        self.packaging_group_id.as_deref()
    }
}
impl ListPackagingConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`ListPackagingConfigurationsInput`](crate::operation::list_packaging_configurations::ListPackagingConfigurationsInput).
    pub fn builder() -> crate::operation::list_packaging_configurations::builders::ListPackagingConfigurationsInputBuilder {
        crate::operation::list_packaging_configurations::builders::ListPackagingConfigurationsInputBuilder::default()
    }
}

/// A builder for [`ListPackagingConfigurationsInput`](crate::operation::list_packaging_configurations::ListPackagingConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPackagingConfigurationsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) packaging_group_id: ::std::option::Option<::std::string::String>,
}
impl ListPackagingConfigurationsInputBuilder {
    /// Upper bound on number of records to return.
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// Upper bound on number of records to return.
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// Upper bound on number of records to return.
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// A token used to resume pagination from the end of a previous request.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// A token used to resume pagination from the end of a previous request.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// A token used to resume pagination from the end of a previous request.
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Returns MediaPackage VOD PackagingConfigurations associated with the specified PackagingGroup.
    pub fn packaging_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.packaging_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// Returns MediaPackage VOD PackagingConfigurations associated with the specified PackagingGroup.
    pub fn set_packaging_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.packaging_group_id = input;
        self
    }
    /// Returns MediaPackage VOD PackagingConfigurations associated with the specified PackagingGroup.
    pub fn get_packaging_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.packaging_group_id
    }
    /// Consumes the builder and constructs a [`ListPackagingConfigurationsInput`](crate::operation::list_packaging_configurations::ListPackagingConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_packaging_configurations::ListPackagingConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_packaging_configurations::ListPackagingConfigurationsInput {
            max_results: self.max_results,
            next_token: self.next_token,
            packaging_group_id: self.packaging_group_id,
        })
    }
}
