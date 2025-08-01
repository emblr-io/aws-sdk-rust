// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of a package that is associated with a domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PackageDetailsForAssociation {
    /// <p>Internal ID of the package that you want to associate with a domain.</p>
    pub package_id: ::std::string::String,
    /// <p>List of package IDs that must be linked to the domain before or simultaneously with the package association.</p>
    pub prerequisite_package_id_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The configuration parameters for associating the package with a domain.</p>
    pub association_configuration: ::std::option::Option<crate::types::PackageAssociationConfiguration>,
}
impl PackageDetailsForAssociation {
    /// <p>Internal ID of the package that you want to associate with a domain.</p>
    pub fn package_id(&self) -> &str {
        use std::ops::Deref;
        self.package_id.deref()
    }
    /// <p>List of package IDs that must be linked to the domain before or simultaneously with the package association.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.prerequisite_package_id_list.is_none()`.
    pub fn prerequisite_package_id_list(&self) -> &[::std::string::String] {
        self.prerequisite_package_id_list.as_deref().unwrap_or_default()
    }
    /// <p>The configuration parameters for associating the package with a domain.</p>
    pub fn association_configuration(&self) -> ::std::option::Option<&crate::types::PackageAssociationConfiguration> {
        self.association_configuration.as_ref()
    }
}
impl PackageDetailsForAssociation {
    /// Creates a new builder-style object to manufacture [`PackageDetailsForAssociation`](crate::types::PackageDetailsForAssociation).
    pub fn builder() -> crate::types::builders::PackageDetailsForAssociationBuilder {
        crate::types::builders::PackageDetailsForAssociationBuilder::default()
    }
}

/// A builder for [`PackageDetailsForAssociation`](crate::types::PackageDetailsForAssociation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PackageDetailsForAssociationBuilder {
    pub(crate) package_id: ::std::option::Option<::std::string::String>,
    pub(crate) prerequisite_package_id_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) association_configuration: ::std::option::Option<crate::types::PackageAssociationConfiguration>,
}
impl PackageDetailsForAssociationBuilder {
    /// <p>Internal ID of the package that you want to associate with a domain.</p>
    /// This field is required.
    pub fn package_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Internal ID of the package that you want to associate with a domain.</p>
    pub fn set_package_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_id = input;
        self
    }
    /// <p>Internal ID of the package that you want to associate with a domain.</p>
    pub fn get_package_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_id
    }
    /// Appends an item to `prerequisite_package_id_list`.
    ///
    /// To override the contents of this collection use [`set_prerequisite_package_id_list`](Self::set_prerequisite_package_id_list).
    ///
    /// <p>List of package IDs that must be linked to the domain before or simultaneously with the package association.</p>
    pub fn prerequisite_package_id_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.prerequisite_package_id_list.unwrap_or_default();
        v.push(input.into());
        self.prerequisite_package_id_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of package IDs that must be linked to the domain before or simultaneously with the package association.</p>
    pub fn set_prerequisite_package_id_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.prerequisite_package_id_list = input;
        self
    }
    /// <p>List of package IDs that must be linked to the domain before or simultaneously with the package association.</p>
    pub fn get_prerequisite_package_id_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.prerequisite_package_id_list
    }
    /// <p>The configuration parameters for associating the package with a domain.</p>
    pub fn association_configuration(mut self, input: crate::types::PackageAssociationConfiguration) -> Self {
        self.association_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration parameters for associating the package with a domain.</p>
    pub fn set_association_configuration(mut self, input: ::std::option::Option<crate::types::PackageAssociationConfiguration>) -> Self {
        self.association_configuration = input;
        self
    }
    /// <p>The configuration parameters for associating the package with a domain.</p>
    pub fn get_association_configuration(&self) -> &::std::option::Option<crate::types::PackageAssociationConfiguration> {
        &self.association_configuration
    }
    /// Consumes the builder and constructs a [`PackageDetailsForAssociation`](crate::types::PackageDetailsForAssociation).
    /// This method will fail if any of the following fields are not set:
    /// - [`package_id`](crate::types::builders::PackageDetailsForAssociationBuilder::package_id)
    pub fn build(self) -> ::std::result::Result<crate::types::PackageDetailsForAssociation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PackageDetailsForAssociation {
            package_id: self.package_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "package_id",
                    "package_id was not specified but it is required when building PackageDetailsForAssociation",
                )
            })?,
            prerequisite_package_id_list: self.prerequisite_package_id_list,
            association_configuration: self.association_configuration,
        })
    }
}
