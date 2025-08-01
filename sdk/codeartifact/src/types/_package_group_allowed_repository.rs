// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an allowed repository for a package group, including its name and origin configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PackageGroupAllowedRepository {
    /// <p>The name of the allowed repository.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The origin configuration restriction type of the allowed repository.</p>
    pub origin_restriction_type: ::std::option::Option<crate::types::PackageGroupOriginRestrictionType>,
}
impl PackageGroupAllowedRepository {
    /// <p>The name of the allowed repository.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The origin configuration restriction type of the allowed repository.</p>
    pub fn origin_restriction_type(&self) -> ::std::option::Option<&crate::types::PackageGroupOriginRestrictionType> {
        self.origin_restriction_type.as_ref()
    }
}
impl PackageGroupAllowedRepository {
    /// Creates a new builder-style object to manufacture [`PackageGroupAllowedRepository`](crate::types::PackageGroupAllowedRepository).
    pub fn builder() -> crate::types::builders::PackageGroupAllowedRepositoryBuilder {
        crate::types::builders::PackageGroupAllowedRepositoryBuilder::default()
    }
}

/// A builder for [`PackageGroupAllowedRepository`](crate::types::PackageGroupAllowedRepository).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PackageGroupAllowedRepositoryBuilder {
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) origin_restriction_type: ::std::option::Option<crate::types::PackageGroupOriginRestrictionType>,
}
impl PackageGroupAllowedRepositoryBuilder {
    /// <p>The name of the allowed repository.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the allowed repository.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the allowed repository.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The origin configuration restriction type of the allowed repository.</p>
    pub fn origin_restriction_type(mut self, input: crate::types::PackageGroupOriginRestrictionType) -> Self {
        self.origin_restriction_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The origin configuration restriction type of the allowed repository.</p>
    pub fn set_origin_restriction_type(mut self, input: ::std::option::Option<crate::types::PackageGroupOriginRestrictionType>) -> Self {
        self.origin_restriction_type = input;
        self
    }
    /// <p>The origin configuration restriction type of the allowed repository.</p>
    pub fn get_origin_restriction_type(&self) -> &::std::option::Option<crate::types::PackageGroupOriginRestrictionType> {
        &self.origin_restriction_type
    }
    /// Consumes the builder and constructs a [`PackageGroupAllowedRepository`](crate::types::PackageGroupAllowedRepository).
    pub fn build(self) -> crate::types::PackageGroupAllowedRepository {
        crate::types::PackageGroupAllowedRepository {
            repository_name: self.repository_name,
            origin_restriction_type: self.origin_restriction_type,
        }
    }
}
