// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RebootDbInstanceInput {
    /// <p>The DB instance identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBInstance.</p></li>
    /// </ul>
    pub db_instance_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the reboot is conducted through a Multi-AZ failover.</p>
    /// <p>Constraint: You can't enable force failover if the instance isn't configured for Multi-AZ.</p>
    pub force_failover: ::std::option::Option<bool>,
}
impl RebootDbInstanceInput {
    /// <p>The DB instance identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBInstance.</p></li>
    /// </ul>
    pub fn db_instance_identifier(&self) -> ::std::option::Option<&str> {
        self.db_instance_identifier.as_deref()
    }
    /// <p>Specifies whether the reboot is conducted through a Multi-AZ failover.</p>
    /// <p>Constraint: You can't enable force failover if the instance isn't configured for Multi-AZ.</p>
    pub fn force_failover(&self) -> ::std::option::Option<bool> {
        self.force_failover
    }
}
impl RebootDbInstanceInput {
    /// Creates a new builder-style object to manufacture [`RebootDbInstanceInput`](crate::operation::reboot_db_instance::RebootDbInstanceInput).
    pub fn builder() -> crate::operation::reboot_db_instance::builders::RebootDbInstanceInputBuilder {
        crate::operation::reboot_db_instance::builders::RebootDbInstanceInputBuilder::default()
    }
}

/// A builder for [`RebootDbInstanceInput`](crate::operation::reboot_db_instance::RebootDbInstanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RebootDbInstanceInputBuilder {
    pub(crate) db_instance_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) force_failover: ::std::option::Option<bool>,
}
impl RebootDbInstanceInputBuilder {
    /// <p>The DB instance identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBInstance.</p></li>
    /// </ul>
    /// This field is required.
    pub fn db_instance_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_instance_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DB instance identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBInstance.</p></li>
    /// </ul>
    pub fn set_db_instance_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_instance_identifier = input;
        self
    }
    /// <p>The DB instance identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBInstance.</p></li>
    /// </ul>
    pub fn get_db_instance_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_instance_identifier
    }
    /// <p>Specifies whether the reboot is conducted through a Multi-AZ failover.</p>
    /// <p>Constraint: You can't enable force failover if the instance isn't configured for Multi-AZ.</p>
    pub fn force_failover(mut self, input: bool) -> Self {
        self.force_failover = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the reboot is conducted through a Multi-AZ failover.</p>
    /// <p>Constraint: You can't enable force failover if the instance isn't configured for Multi-AZ.</p>
    pub fn set_force_failover(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force_failover = input;
        self
    }
    /// <p>Specifies whether the reboot is conducted through a Multi-AZ failover.</p>
    /// <p>Constraint: You can't enable force failover if the instance isn't configured for Multi-AZ.</p>
    pub fn get_force_failover(&self) -> &::std::option::Option<bool> {
        &self.force_failover
    }
    /// Consumes the builder and constructs a [`RebootDbInstanceInput`](crate::operation::reboot_db_instance::RebootDbInstanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::reboot_db_instance::RebootDbInstanceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::reboot_db_instance::RebootDbInstanceInput {
            db_instance_identifier: self.db_instance_identifier,
            force_failover: self.force_failover,
        })
    }
}
