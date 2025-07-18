// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInventoryInput {
    /// <p>The name of the custom inventory type for which you want to delete either all previously collected data or the inventory type itself.</p>
    pub type_name: ::std::option::Option<::std::string::String>,
    /// <p>Use the <code>SchemaDeleteOption</code> to delete a custom inventory type (schema). If you don't choose this option, the system only deletes existing inventory data associated with the custom inventory type. Choose one of the following options:</p>
    /// <p>DisableSchema: If you choose this option, the system ignores all inventory data for the specified version, and any earlier versions. To enable this schema again, you must call the <code>PutInventory</code> operation for a version greater than the disabled version.</p>
    /// <p>DeleteSchema: This option deletes the specified custom type from the Inventory service. You can recreate the schema later, if you want.</p>
    pub schema_delete_option: ::std::option::Option<crate::types::InventorySchemaDeleteOption>,
    /// <p>Use this option to view a summary of the deletion request without deleting any data or the data type. This option is useful when you only want to understand what will be deleted. Once you validate that the data to be deleted is what you intend to delete, you can run the same command without specifying the <code>DryRun</code> option.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>User-provided idempotency token.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl DeleteInventoryInput {
    /// <p>The name of the custom inventory type for which you want to delete either all previously collected data or the inventory type itself.</p>
    pub fn type_name(&self) -> ::std::option::Option<&str> {
        self.type_name.as_deref()
    }
    /// <p>Use the <code>SchemaDeleteOption</code> to delete a custom inventory type (schema). If you don't choose this option, the system only deletes existing inventory data associated with the custom inventory type. Choose one of the following options:</p>
    /// <p>DisableSchema: If you choose this option, the system ignores all inventory data for the specified version, and any earlier versions. To enable this schema again, you must call the <code>PutInventory</code> operation for a version greater than the disabled version.</p>
    /// <p>DeleteSchema: This option deletes the specified custom type from the Inventory service. You can recreate the schema later, if you want.</p>
    pub fn schema_delete_option(&self) -> ::std::option::Option<&crate::types::InventorySchemaDeleteOption> {
        self.schema_delete_option.as_ref()
    }
    /// <p>Use this option to view a summary of the deletion request without deleting any data or the data type. This option is useful when you only want to understand what will be deleted. Once you validate that the data to be deleted is what you intend to delete, you can run the same command without specifying the <code>DryRun</code> option.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>User-provided idempotency token.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl DeleteInventoryInput {
    /// Creates a new builder-style object to manufacture [`DeleteInventoryInput`](crate::operation::delete_inventory::DeleteInventoryInput).
    pub fn builder() -> crate::operation::delete_inventory::builders::DeleteInventoryInputBuilder {
        crate::operation::delete_inventory::builders::DeleteInventoryInputBuilder::default()
    }
}

/// A builder for [`DeleteInventoryInput`](crate::operation::delete_inventory::DeleteInventoryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInventoryInputBuilder {
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) schema_delete_option: ::std::option::Option<crate::types::InventorySchemaDeleteOption>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl DeleteInventoryInputBuilder {
    /// <p>The name of the custom inventory type for which you want to delete either all previously collected data or the inventory type itself.</p>
    /// This field is required.
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom inventory type for which you want to delete either all previously collected data or the inventory type itself.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the custom inventory type for which you want to delete either all previously collected data or the inventory type itself.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>Use the <code>SchemaDeleteOption</code> to delete a custom inventory type (schema). If you don't choose this option, the system only deletes existing inventory data associated with the custom inventory type. Choose one of the following options:</p>
    /// <p>DisableSchema: If you choose this option, the system ignores all inventory data for the specified version, and any earlier versions. To enable this schema again, you must call the <code>PutInventory</code> operation for a version greater than the disabled version.</p>
    /// <p>DeleteSchema: This option deletes the specified custom type from the Inventory service. You can recreate the schema later, if you want.</p>
    pub fn schema_delete_option(mut self, input: crate::types::InventorySchemaDeleteOption) -> Self {
        self.schema_delete_option = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use the <code>SchemaDeleteOption</code> to delete a custom inventory type (schema). If you don't choose this option, the system only deletes existing inventory data associated with the custom inventory type. Choose one of the following options:</p>
    /// <p>DisableSchema: If you choose this option, the system ignores all inventory data for the specified version, and any earlier versions. To enable this schema again, you must call the <code>PutInventory</code> operation for a version greater than the disabled version.</p>
    /// <p>DeleteSchema: This option deletes the specified custom type from the Inventory service. You can recreate the schema later, if you want.</p>
    pub fn set_schema_delete_option(mut self, input: ::std::option::Option<crate::types::InventorySchemaDeleteOption>) -> Self {
        self.schema_delete_option = input;
        self
    }
    /// <p>Use the <code>SchemaDeleteOption</code> to delete a custom inventory type (schema). If you don't choose this option, the system only deletes existing inventory data associated with the custom inventory type. Choose one of the following options:</p>
    /// <p>DisableSchema: If you choose this option, the system ignores all inventory data for the specified version, and any earlier versions. To enable this schema again, you must call the <code>PutInventory</code> operation for a version greater than the disabled version.</p>
    /// <p>DeleteSchema: This option deletes the specified custom type from the Inventory service. You can recreate the schema later, if you want.</p>
    pub fn get_schema_delete_option(&self) -> &::std::option::Option<crate::types::InventorySchemaDeleteOption> {
        &self.schema_delete_option
    }
    /// <p>Use this option to view a summary of the deletion request without deleting any data or the data type. This option is useful when you only want to understand what will be deleted. Once you validate that the data to be deleted is what you intend to delete, you can run the same command without specifying the <code>DryRun</code> option.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this option to view a summary of the deletion request without deleting any data or the data type. This option is useful when you only want to understand what will be deleted. Once you validate that the data to be deleted is what you intend to delete, you can run the same command without specifying the <code>DryRun</code> option.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Use this option to view a summary of the deletion request without deleting any data or the data type. This option is useful when you only want to understand what will be deleted. Once you validate that the data to be deleted is what you intend to delete, you can run the same command without specifying the <code>DryRun</code> option.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>User-provided idempotency token.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>User-provided idempotency token.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>User-provided idempotency token.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`DeleteInventoryInput`](crate::operation::delete_inventory::DeleteInventoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_inventory::DeleteInventoryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_inventory::DeleteInventoryInput {
            type_name: self.type_name,
            schema_delete_option: self.schema_delete_option,
            dry_run: self.dry_run,
            client_token: self.client_token,
        })
    }
}
