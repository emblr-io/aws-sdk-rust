// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identification hints.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdentificationHints {
    /// <p>FQDN address identification hint.</p>
    pub fqdn: ::std::option::Option<::std::string::String>,
    /// <p>Hostname identification hint.</p>
    pub hostname: ::std::option::Option<::std::string::String>,
    /// <p>vmWare UUID identification hint.</p>
    pub vm_ware_uuid: ::std::option::Option<::std::string::String>,
    /// <p>AWS Instance ID identification hint.</p>
    pub aws_instance_id: ::std::option::Option<::std::string::String>,
    /// <p>vCenter VM path identification hint.</p>
    pub vm_path: ::std::option::Option<::std::string::String>,
}
impl IdentificationHints {
    /// <p>FQDN address identification hint.</p>
    pub fn fqdn(&self) -> ::std::option::Option<&str> {
        self.fqdn.as_deref()
    }
    /// <p>Hostname identification hint.</p>
    pub fn hostname(&self) -> ::std::option::Option<&str> {
        self.hostname.as_deref()
    }
    /// <p>vmWare UUID identification hint.</p>
    pub fn vm_ware_uuid(&self) -> ::std::option::Option<&str> {
        self.vm_ware_uuid.as_deref()
    }
    /// <p>AWS Instance ID identification hint.</p>
    pub fn aws_instance_id(&self) -> ::std::option::Option<&str> {
        self.aws_instance_id.as_deref()
    }
    /// <p>vCenter VM path identification hint.</p>
    pub fn vm_path(&self) -> ::std::option::Option<&str> {
        self.vm_path.as_deref()
    }
}
impl IdentificationHints {
    /// Creates a new builder-style object to manufacture [`IdentificationHints`](crate::types::IdentificationHints).
    pub fn builder() -> crate::types::builders::IdentificationHintsBuilder {
        crate::types::builders::IdentificationHintsBuilder::default()
    }
}

/// A builder for [`IdentificationHints`](crate::types::IdentificationHints).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdentificationHintsBuilder {
    pub(crate) fqdn: ::std::option::Option<::std::string::String>,
    pub(crate) hostname: ::std::option::Option<::std::string::String>,
    pub(crate) vm_ware_uuid: ::std::option::Option<::std::string::String>,
    pub(crate) aws_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) vm_path: ::std::option::Option<::std::string::String>,
}
impl IdentificationHintsBuilder {
    /// <p>FQDN address identification hint.</p>
    pub fn fqdn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fqdn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>FQDN address identification hint.</p>
    pub fn set_fqdn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fqdn = input;
        self
    }
    /// <p>FQDN address identification hint.</p>
    pub fn get_fqdn(&self) -> &::std::option::Option<::std::string::String> {
        &self.fqdn
    }
    /// <p>Hostname identification hint.</p>
    pub fn hostname(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hostname = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Hostname identification hint.</p>
    pub fn set_hostname(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hostname = input;
        self
    }
    /// <p>Hostname identification hint.</p>
    pub fn get_hostname(&self) -> &::std::option::Option<::std::string::String> {
        &self.hostname
    }
    /// <p>vmWare UUID identification hint.</p>
    pub fn vm_ware_uuid(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vm_ware_uuid = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>vmWare UUID identification hint.</p>
    pub fn set_vm_ware_uuid(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vm_ware_uuid = input;
        self
    }
    /// <p>vmWare UUID identification hint.</p>
    pub fn get_vm_ware_uuid(&self) -> &::std::option::Option<::std::string::String> {
        &self.vm_ware_uuid
    }
    /// <p>AWS Instance ID identification hint.</p>
    pub fn aws_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>AWS Instance ID identification hint.</p>
    pub fn set_aws_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_instance_id = input;
        self
    }
    /// <p>AWS Instance ID identification hint.</p>
    pub fn get_aws_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_instance_id
    }
    /// <p>vCenter VM path identification hint.</p>
    pub fn vm_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vm_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>vCenter VM path identification hint.</p>
    pub fn set_vm_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vm_path = input;
        self
    }
    /// <p>vCenter VM path identification hint.</p>
    pub fn get_vm_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.vm_path
    }
    /// Consumes the builder and constructs a [`IdentificationHints`](crate::types::IdentificationHints).
    pub fn build(self) -> crate::types::IdentificationHints {
        crate::types::IdentificationHints {
            fqdn: self.fqdn,
            hostname: self.hostname,
            vm_ware_uuid: self.vm_ware_uuid,
            aws_instance_id: self.aws_instance_id,
            vm_path: self.vm_path,
        }
    }
}
