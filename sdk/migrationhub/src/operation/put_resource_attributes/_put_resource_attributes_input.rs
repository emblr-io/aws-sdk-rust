// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutResourceAttributesInput {
    /// <p>The name of the ProgressUpdateStream.</p>
    pub progress_update_stream: ::std::option::Option<::std::string::String>,
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub migration_task_name: ::std::option::Option<::std::string::String>,
    /// <p>Information about the resource that is being migrated. This data will be used to map the task to a resource in the Application Discovery Service repository.</p><note>
    /// <p>Takes the object array of <code>ResourceAttribute</code> where the <code>Type</code> field is reserved for the following values: <code>IPV4_ADDRESS | IPV6_ADDRESS | MAC_ADDRESS | FQDN | VM_MANAGER_ID | VM_MANAGED_OBJECT_REFERENCE | VM_NAME | VM_PATH | BIOS_ID | MOTHERBOARD_SERIAL_NUMBER</code> where the identifying value can be a string up to 256 characters.</p>
    /// </note> <important>
    /// <ul>
    /// <li>
    /// <p>If any "VM" related value is set for a <code>ResourceAttribute</code> object, it is required that <code>VM_MANAGER_ID</code>, as a minimum, is always set. If <code>VM_MANAGER_ID</code> is not set, then all "VM" fields will be discarded and "VM" fields will not be used for matching the migration task to a server in Application Discovery Service repository. See the <a href="https://docs.aws.amazon.com/migrationhub/latest/ug/API_PutResourceAttributes.html#API_PutResourceAttributes_Examples">Example</a> section below for a use case of specifying "VM" related values.</p></li>
    /// <li>
    /// <p>If a server you are trying to match has multiple IP or MAC addresses, you should provide as many as you know in separate type/value pairs passed to the <code>ResourceAttributeList</code> parameter to maximize the chances of matching.</p></li>
    /// </ul>
    /// </important>
    pub resource_attribute_list: ::std::option::Option<::std::vec::Vec<crate::types::ResourceAttribute>>,
    /// <p>Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl PutResourceAttributesInput {
    /// <p>The name of the ProgressUpdateStream.</p>
    pub fn progress_update_stream(&self) -> ::std::option::Option<&str> {
        self.progress_update_stream.as_deref()
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub fn migration_task_name(&self) -> ::std::option::Option<&str> {
        self.migration_task_name.as_deref()
    }
    /// <p>Information about the resource that is being migrated. This data will be used to map the task to a resource in the Application Discovery Service repository.</p><note>
    /// <p>Takes the object array of <code>ResourceAttribute</code> where the <code>Type</code> field is reserved for the following values: <code>IPV4_ADDRESS | IPV6_ADDRESS | MAC_ADDRESS | FQDN | VM_MANAGER_ID | VM_MANAGED_OBJECT_REFERENCE | VM_NAME | VM_PATH | BIOS_ID | MOTHERBOARD_SERIAL_NUMBER</code> where the identifying value can be a string up to 256 characters.</p>
    /// </note> <important>
    /// <ul>
    /// <li>
    /// <p>If any "VM" related value is set for a <code>ResourceAttribute</code> object, it is required that <code>VM_MANAGER_ID</code>, as a minimum, is always set. If <code>VM_MANAGER_ID</code> is not set, then all "VM" fields will be discarded and "VM" fields will not be used for matching the migration task to a server in Application Discovery Service repository. See the <a href="https://docs.aws.amazon.com/migrationhub/latest/ug/API_PutResourceAttributes.html#API_PutResourceAttributes_Examples">Example</a> section below for a use case of specifying "VM" related values.</p></li>
    /// <li>
    /// <p>If a server you are trying to match has multiple IP or MAC addresses, you should provide as many as you know in separate type/value pairs passed to the <code>ResourceAttributeList</code> parameter to maximize the chances of matching.</p></li>
    /// </ul>
    /// </important>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_attribute_list.is_none()`.
    pub fn resource_attribute_list(&self) -> &[crate::types::ResourceAttribute] {
        self.resource_attribute_list.as_deref().unwrap_or_default()
    }
    /// <p>Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl PutResourceAttributesInput {
    /// Creates a new builder-style object to manufacture [`PutResourceAttributesInput`](crate::operation::put_resource_attributes::PutResourceAttributesInput).
    pub fn builder() -> crate::operation::put_resource_attributes::builders::PutResourceAttributesInputBuilder {
        crate::operation::put_resource_attributes::builders::PutResourceAttributesInputBuilder::default()
    }
}

/// A builder for [`PutResourceAttributesInput`](crate::operation::put_resource_attributes::PutResourceAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutResourceAttributesInputBuilder {
    pub(crate) progress_update_stream: ::std::option::Option<::std::string::String>,
    pub(crate) migration_task_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_attribute_list: ::std::option::Option<::std::vec::Vec<crate::types::ResourceAttribute>>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl PutResourceAttributesInputBuilder {
    /// <p>The name of the ProgressUpdateStream.</p>
    /// This field is required.
    pub fn progress_update_stream(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.progress_update_stream = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ProgressUpdateStream.</p>
    pub fn set_progress_update_stream(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.progress_update_stream = input;
        self
    }
    /// <p>The name of the ProgressUpdateStream.</p>
    pub fn get_progress_update_stream(&self) -> &::std::option::Option<::std::string::String> {
        &self.progress_update_stream
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    /// This field is required.
    pub fn migration_task_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.migration_task_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub fn set_migration_task_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.migration_task_name = input;
        self
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub fn get_migration_task_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.migration_task_name
    }
    /// Appends an item to `resource_attribute_list`.
    ///
    /// To override the contents of this collection use [`set_resource_attribute_list`](Self::set_resource_attribute_list).
    ///
    /// <p>Information about the resource that is being migrated. This data will be used to map the task to a resource in the Application Discovery Service repository.</p><note>
    /// <p>Takes the object array of <code>ResourceAttribute</code> where the <code>Type</code> field is reserved for the following values: <code>IPV4_ADDRESS | IPV6_ADDRESS | MAC_ADDRESS | FQDN | VM_MANAGER_ID | VM_MANAGED_OBJECT_REFERENCE | VM_NAME | VM_PATH | BIOS_ID | MOTHERBOARD_SERIAL_NUMBER</code> where the identifying value can be a string up to 256 characters.</p>
    /// </note> <important>
    /// <ul>
    /// <li>
    /// <p>If any "VM" related value is set for a <code>ResourceAttribute</code> object, it is required that <code>VM_MANAGER_ID</code>, as a minimum, is always set. If <code>VM_MANAGER_ID</code> is not set, then all "VM" fields will be discarded and "VM" fields will not be used for matching the migration task to a server in Application Discovery Service repository. See the <a href="https://docs.aws.amazon.com/migrationhub/latest/ug/API_PutResourceAttributes.html#API_PutResourceAttributes_Examples">Example</a> section below for a use case of specifying "VM" related values.</p></li>
    /// <li>
    /// <p>If a server you are trying to match has multiple IP or MAC addresses, you should provide as many as you know in separate type/value pairs passed to the <code>ResourceAttributeList</code> parameter to maximize the chances of matching.</p></li>
    /// </ul>
    /// </important>
    pub fn resource_attribute_list(mut self, input: crate::types::ResourceAttribute) -> Self {
        let mut v = self.resource_attribute_list.unwrap_or_default();
        v.push(input);
        self.resource_attribute_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the resource that is being migrated. This data will be used to map the task to a resource in the Application Discovery Service repository.</p><note>
    /// <p>Takes the object array of <code>ResourceAttribute</code> where the <code>Type</code> field is reserved for the following values: <code>IPV4_ADDRESS | IPV6_ADDRESS | MAC_ADDRESS | FQDN | VM_MANAGER_ID | VM_MANAGED_OBJECT_REFERENCE | VM_NAME | VM_PATH | BIOS_ID | MOTHERBOARD_SERIAL_NUMBER</code> where the identifying value can be a string up to 256 characters.</p>
    /// </note> <important>
    /// <ul>
    /// <li>
    /// <p>If any "VM" related value is set for a <code>ResourceAttribute</code> object, it is required that <code>VM_MANAGER_ID</code>, as a minimum, is always set. If <code>VM_MANAGER_ID</code> is not set, then all "VM" fields will be discarded and "VM" fields will not be used for matching the migration task to a server in Application Discovery Service repository. See the <a href="https://docs.aws.amazon.com/migrationhub/latest/ug/API_PutResourceAttributes.html#API_PutResourceAttributes_Examples">Example</a> section below for a use case of specifying "VM" related values.</p></li>
    /// <li>
    /// <p>If a server you are trying to match has multiple IP or MAC addresses, you should provide as many as you know in separate type/value pairs passed to the <code>ResourceAttributeList</code> parameter to maximize the chances of matching.</p></li>
    /// </ul>
    /// </important>
    pub fn set_resource_attribute_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceAttribute>>) -> Self {
        self.resource_attribute_list = input;
        self
    }
    /// <p>Information about the resource that is being migrated. This data will be used to map the task to a resource in the Application Discovery Service repository.</p><note>
    /// <p>Takes the object array of <code>ResourceAttribute</code> where the <code>Type</code> field is reserved for the following values: <code>IPV4_ADDRESS | IPV6_ADDRESS | MAC_ADDRESS | FQDN | VM_MANAGER_ID | VM_MANAGED_OBJECT_REFERENCE | VM_NAME | VM_PATH | BIOS_ID | MOTHERBOARD_SERIAL_NUMBER</code> where the identifying value can be a string up to 256 characters.</p>
    /// </note> <important>
    /// <ul>
    /// <li>
    /// <p>If any "VM" related value is set for a <code>ResourceAttribute</code> object, it is required that <code>VM_MANAGER_ID</code>, as a minimum, is always set. If <code>VM_MANAGER_ID</code> is not set, then all "VM" fields will be discarded and "VM" fields will not be used for matching the migration task to a server in Application Discovery Service repository. See the <a href="https://docs.aws.amazon.com/migrationhub/latest/ug/API_PutResourceAttributes.html#API_PutResourceAttributes_Examples">Example</a> section below for a use case of specifying "VM" related values.</p></li>
    /// <li>
    /// <p>If a server you are trying to match has multiple IP or MAC addresses, you should provide as many as you know in separate type/value pairs passed to the <code>ResourceAttributeList</code> parameter to maximize the chances of matching.</p></li>
    /// </ul>
    /// </important>
    pub fn get_resource_attribute_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceAttribute>> {
        &self.resource_attribute_list
    }
    /// <p>Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Optional boolean flag to indicate whether any effect should take place. Used to test if the caller has permission to make the call.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`PutResourceAttributesInput`](crate::operation::put_resource_attributes::PutResourceAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_resource_attributes::PutResourceAttributesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::put_resource_attributes::PutResourceAttributesInput {
            progress_update_stream: self.progress_update_stream,
            migration_task_name: self.migration_task_name,
            resource_attribute_list: self.resource_attribute_list,
            dry_run: self.dry_run,
        })
    }
}
