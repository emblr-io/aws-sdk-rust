// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePartnerInput {
    /// <p>The Amazon Web Services account ID that owns the cluster.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The cluster identifier of the cluster that receives data from the partner.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the database that receives data from the partner.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the partner that is authorized to send data.</p>
    pub partner_name: ::std::option::Option<::std::string::String>,
}
impl DeletePartnerInput {
    /// <p>The Amazon Web Services account ID that owns the cluster.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The cluster identifier of the cluster that receives data from the partner.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The name of the database that receives data from the partner.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the partner that is authorized to send data.</p>
    pub fn partner_name(&self) -> ::std::option::Option<&str> {
        self.partner_name.as_deref()
    }
}
impl DeletePartnerInput {
    /// Creates a new builder-style object to manufacture [`DeletePartnerInput`](crate::operation::delete_partner::DeletePartnerInput).
    pub fn builder() -> crate::operation::delete_partner::builders::DeletePartnerInputBuilder {
        crate::operation::delete_partner::builders::DeletePartnerInputBuilder::default()
    }
}

/// A builder for [`DeletePartnerInput`](crate::operation::delete_partner::DeletePartnerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePartnerInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) partner_name: ::std::option::Option<::std::string::String>,
}
impl DeletePartnerInputBuilder {
    /// <p>The Amazon Web Services account ID that owns the cluster.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID that owns the cluster.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID that owns the cluster.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The cluster identifier of the cluster that receives data from the partner.</p>
    /// This field is required.
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier of the cluster that receives data from the partner.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The cluster identifier of the cluster that receives data from the partner.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The name of the database that receives data from the partner.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database that receives data from the partner.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the database that receives data from the partner.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the partner that is authorized to send data.</p>
    /// This field is required.
    pub fn partner_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.partner_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the partner that is authorized to send data.</p>
    pub fn set_partner_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.partner_name = input;
        self
    }
    /// <p>The name of the partner that is authorized to send data.</p>
    pub fn get_partner_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.partner_name
    }
    /// Consumes the builder and constructs a [`DeletePartnerInput`](crate::operation::delete_partner::DeletePartnerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_partner::DeletePartnerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_partner::DeletePartnerInput {
            account_id: self.account_id,
            cluster_identifier: self.cluster_identifier,
            database_name: self.database_name,
            partner_name: self.partner_name,
        })
    }
}
