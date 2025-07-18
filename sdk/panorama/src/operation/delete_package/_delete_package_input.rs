// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePackageInput {
    /// <p>The package's ID.</p>
    pub package_id: ::std::option::Option<::std::string::String>,
    /// <p>Delete the package even if it has artifacts stored in its access point. Deletes the package's artifacts from Amazon S3.</p>
    pub force_delete: ::std::option::Option<bool>,
}
impl DeletePackageInput {
    /// <p>The package's ID.</p>
    pub fn package_id(&self) -> ::std::option::Option<&str> {
        self.package_id.as_deref()
    }
    /// <p>Delete the package even if it has artifacts stored in its access point. Deletes the package's artifacts from Amazon S3.</p>
    pub fn force_delete(&self) -> ::std::option::Option<bool> {
        self.force_delete
    }
}
impl DeletePackageInput {
    /// Creates a new builder-style object to manufacture [`DeletePackageInput`](crate::operation::delete_package::DeletePackageInput).
    pub fn builder() -> crate::operation::delete_package::builders::DeletePackageInputBuilder {
        crate::operation::delete_package::builders::DeletePackageInputBuilder::default()
    }
}

/// A builder for [`DeletePackageInput`](crate::operation::delete_package::DeletePackageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePackageInputBuilder {
    pub(crate) package_id: ::std::option::Option<::std::string::String>,
    pub(crate) force_delete: ::std::option::Option<bool>,
}
impl DeletePackageInputBuilder {
    /// <p>The package's ID.</p>
    /// This field is required.
    pub fn package_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The package's ID.</p>
    pub fn set_package_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_id = input;
        self
    }
    /// <p>The package's ID.</p>
    pub fn get_package_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_id
    }
    /// <p>Delete the package even if it has artifacts stored in its access point. Deletes the package's artifacts from Amazon S3.</p>
    pub fn force_delete(mut self, input: bool) -> Self {
        self.force_delete = ::std::option::Option::Some(input);
        self
    }
    /// <p>Delete the package even if it has artifacts stored in its access point. Deletes the package's artifacts from Amazon S3.</p>
    pub fn set_force_delete(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force_delete = input;
        self
    }
    /// <p>Delete the package even if it has artifacts stored in its access point. Deletes the package's artifacts from Amazon S3.</p>
    pub fn get_force_delete(&self) -> &::std::option::Option<bool> {
        &self.force_delete
    }
    /// Consumes the builder and constructs a [`DeletePackageInput`](crate::operation::delete_package::DeletePackageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_package::DeletePackageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_package::DeletePackageInput {
            package_id: self.package_id,
            force_delete: self.force_delete,
        })
    }
}
