// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateOpsItemRelatedItemInput {
    /// <p>The ID of the OpsItem for which you want to delete an association between the OpsItem and a related item.</p>
    pub ops_item_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the association for which you want to delete an association between the OpsItem and a related item.</p>
    pub association_id: ::std::option::Option<::std::string::String>,
}
impl DisassociateOpsItemRelatedItemInput {
    /// <p>The ID of the OpsItem for which you want to delete an association between the OpsItem and a related item.</p>
    pub fn ops_item_id(&self) -> ::std::option::Option<&str> {
        self.ops_item_id.as_deref()
    }
    /// <p>The ID of the association for which you want to delete an association between the OpsItem and a related item.</p>
    pub fn association_id(&self) -> ::std::option::Option<&str> {
        self.association_id.as_deref()
    }
}
impl DisassociateOpsItemRelatedItemInput {
    /// Creates a new builder-style object to manufacture [`DisassociateOpsItemRelatedItemInput`](crate::operation::disassociate_ops_item_related_item::DisassociateOpsItemRelatedItemInput).
    pub fn builder() -> crate::operation::disassociate_ops_item_related_item::builders::DisassociateOpsItemRelatedItemInputBuilder {
        crate::operation::disassociate_ops_item_related_item::builders::DisassociateOpsItemRelatedItemInputBuilder::default()
    }
}

/// A builder for [`DisassociateOpsItemRelatedItemInput`](crate::operation::disassociate_ops_item_related_item::DisassociateOpsItemRelatedItemInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateOpsItemRelatedItemInputBuilder {
    pub(crate) ops_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) association_id: ::std::option::Option<::std::string::String>,
}
impl DisassociateOpsItemRelatedItemInputBuilder {
    /// <p>The ID of the OpsItem for which you want to delete an association between the OpsItem and a related item.</p>
    /// This field is required.
    pub fn ops_item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ops_item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the OpsItem for which you want to delete an association between the OpsItem and a related item.</p>
    pub fn set_ops_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ops_item_id = input;
        self
    }
    /// <p>The ID of the OpsItem for which you want to delete an association between the OpsItem and a related item.</p>
    pub fn get_ops_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ops_item_id
    }
    /// <p>The ID of the association for which you want to delete an association between the OpsItem and a related item.</p>
    /// This field is required.
    pub fn association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the association for which you want to delete an association between the OpsItem and a related item.</p>
    pub fn set_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_id = input;
        self
    }
    /// <p>The ID of the association for which you want to delete an association between the OpsItem and a related item.</p>
    pub fn get_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_id
    }
    /// Consumes the builder and constructs a [`DisassociateOpsItemRelatedItemInput`](crate::operation::disassociate_ops_item_related_item::DisassociateOpsItemRelatedItemInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_ops_item_related_item::DisassociateOpsItemRelatedItemInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::disassociate_ops_item_related_item::DisassociateOpsItemRelatedItemInput {
                ops_item_id: self.ops_item_id,
                association_id: self.association_id,
            },
        )
    }
}
