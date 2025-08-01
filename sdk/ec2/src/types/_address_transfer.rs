// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details on the Elastic IP address transfer. For more information, see <a href="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-eips.html#transfer-EIPs-intro">Transfer Elastic IP addresses</a> in the <i>Amazon VPC User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddressTransfer {
    /// <p>The Elastic IP address being transferred.</p>
    pub public_ip: ::std::option::Option<::std::string::String>,
    /// <p>The allocation ID of an Elastic IP address.</p>
    pub allocation_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the account that you want to transfer the Elastic IP address to.</p>
    pub transfer_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when the Elastic IP address transfer expired. When the source account starts the transfer, the transfer account has seven hours to allocate the Elastic IP address to complete the transfer, or the Elastic IP address will return to its original owner.</p>
    pub transfer_offer_expiration_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp when the Elastic IP address transfer was accepted.</p>
    pub transfer_offer_accepted_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Elastic IP address transfer status.</p>
    pub address_transfer_status: ::std::option::Option<crate::types::AddressTransferStatus>,
}
impl AddressTransfer {
    /// <p>The Elastic IP address being transferred.</p>
    pub fn public_ip(&self) -> ::std::option::Option<&str> {
        self.public_ip.as_deref()
    }
    /// <p>The allocation ID of an Elastic IP address.</p>
    pub fn allocation_id(&self) -> ::std::option::Option<&str> {
        self.allocation_id.as_deref()
    }
    /// <p>The ID of the account that you want to transfer the Elastic IP address to.</p>
    pub fn transfer_account_id(&self) -> ::std::option::Option<&str> {
        self.transfer_account_id.as_deref()
    }
    /// <p>The timestamp when the Elastic IP address transfer expired. When the source account starts the transfer, the transfer account has seven hours to allocate the Elastic IP address to complete the transfer, or the Elastic IP address will return to its original owner.</p>
    pub fn transfer_offer_expiration_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.transfer_offer_expiration_timestamp.as_ref()
    }
    /// <p>The timestamp when the Elastic IP address transfer was accepted.</p>
    pub fn transfer_offer_accepted_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.transfer_offer_accepted_timestamp.as_ref()
    }
    /// <p>The Elastic IP address transfer status.</p>
    pub fn address_transfer_status(&self) -> ::std::option::Option<&crate::types::AddressTransferStatus> {
        self.address_transfer_status.as_ref()
    }
}
impl AddressTransfer {
    /// Creates a new builder-style object to manufacture [`AddressTransfer`](crate::types::AddressTransfer).
    pub fn builder() -> crate::types::builders::AddressTransferBuilder {
        crate::types::builders::AddressTransferBuilder::default()
    }
}

/// A builder for [`AddressTransfer`](crate::types::AddressTransfer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddressTransferBuilder {
    pub(crate) public_ip: ::std::option::Option<::std::string::String>,
    pub(crate) allocation_id: ::std::option::Option<::std::string::String>,
    pub(crate) transfer_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) transfer_offer_expiration_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) transfer_offer_accepted_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) address_transfer_status: ::std::option::Option<crate::types::AddressTransferStatus>,
}
impl AddressTransferBuilder {
    /// <p>The Elastic IP address being transferred.</p>
    pub fn public_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elastic IP address being transferred.</p>
    pub fn set_public_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_ip = input;
        self
    }
    /// <p>The Elastic IP address being transferred.</p>
    pub fn get_public_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_ip
    }
    /// <p>The allocation ID of an Elastic IP address.</p>
    pub fn allocation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allocation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The allocation ID of an Elastic IP address.</p>
    pub fn set_allocation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allocation_id = input;
        self
    }
    /// <p>The allocation ID of an Elastic IP address.</p>
    pub fn get_allocation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.allocation_id
    }
    /// <p>The ID of the account that you want to transfer the Elastic IP address to.</p>
    pub fn transfer_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transfer_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the account that you want to transfer the Elastic IP address to.</p>
    pub fn set_transfer_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transfer_account_id = input;
        self
    }
    /// <p>The ID of the account that you want to transfer the Elastic IP address to.</p>
    pub fn get_transfer_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transfer_account_id
    }
    /// <p>The timestamp when the Elastic IP address transfer expired. When the source account starts the transfer, the transfer account has seven hours to allocate the Elastic IP address to complete the transfer, or the Elastic IP address will return to its original owner.</p>
    pub fn transfer_offer_expiration_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.transfer_offer_expiration_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the Elastic IP address transfer expired. When the source account starts the transfer, the transfer account has seven hours to allocate the Elastic IP address to complete the transfer, or the Elastic IP address will return to its original owner.</p>
    pub fn set_transfer_offer_expiration_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.transfer_offer_expiration_timestamp = input;
        self
    }
    /// <p>The timestamp when the Elastic IP address transfer expired. When the source account starts the transfer, the transfer account has seven hours to allocate the Elastic IP address to complete the transfer, or the Elastic IP address will return to its original owner.</p>
    pub fn get_transfer_offer_expiration_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.transfer_offer_expiration_timestamp
    }
    /// <p>The timestamp when the Elastic IP address transfer was accepted.</p>
    pub fn transfer_offer_accepted_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.transfer_offer_accepted_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the Elastic IP address transfer was accepted.</p>
    pub fn set_transfer_offer_accepted_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.transfer_offer_accepted_timestamp = input;
        self
    }
    /// <p>The timestamp when the Elastic IP address transfer was accepted.</p>
    pub fn get_transfer_offer_accepted_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.transfer_offer_accepted_timestamp
    }
    /// <p>The Elastic IP address transfer status.</p>
    pub fn address_transfer_status(mut self, input: crate::types::AddressTransferStatus) -> Self {
        self.address_transfer_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Elastic IP address transfer status.</p>
    pub fn set_address_transfer_status(mut self, input: ::std::option::Option<crate::types::AddressTransferStatus>) -> Self {
        self.address_transfer_status = input;
        self
    }
    /// <p>The Elastic IP address transfer status.</p>
    pub fn get_address_transfer_status(&self) -> &::std::option::Option<crate::types::AddressTransferStatus> {
        &self.address_transfer_status
    }
    /// Consumes the builder and constructs a [`AddressTransfer`](crate::types::AddressTransfer).
    pub fn build(self) -> crate::types::AddressTransfer {
        crate::types::AddressTransfer {
            public_ip: self.public_ip,
            allocation_id: self.allocation_id,
            transfer_account_id: self.transfer_account_id,
            transfer_offer_expiration_timestamp: self.transfer_offer_expiration_timestamp,
            transfer_offer_accepted_timestamp: self.transfer_offer_accepted_timestamp,
            address_transfer_status: self.address_transfer_status,
        }
    }
}
