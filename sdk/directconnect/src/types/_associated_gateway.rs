// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the associated gateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociatedGateway {
    /// <p>The ID of the associated gateway.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The type of associated gateway.</p>
    pub r#type: ::std::option::Option<crate::types::GatewayType>,
    /// <p>The ID of the Amazon Web Services account that owns the associated virtual private gateway or transit gateway.</p>
    pub owner_account: ::std::option::Option<::std::string::String>,
    /// <p>The Region where the associated gateway is located.</p>
    pub region: ::std::option::Option<::std::string::String>,
}
impl AssociatedGateway {
    /// <p>The ID of the associated gateway.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The type of associated gateway.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::GatewayType> {
        self.r#type.as_ref()
    }
    /// <p>The ID of the Amazon Web Services account that owns the associated virtual private gateway or transit gateway.</p>
    pub fn owner_account(&self) -> ::std::option::Option<&str> {
        self.owner_account.as_deref()
    }
    /// <p>The Region where the associated gateway is located.</p>
    pub fn region(&self) -> ::std::option::Option<&str> {
        self.region.as_deref()
    }
}
impl AssociatedGateway {
    /// Creates a new builder-style object to manufacture [`AssociatedGateway`](crate::types::AssociatedGateway).
    pub fn builder() -> crate::types::builders::AssociatedGatewayBuilder {
        crate::types::builders::AssociatedGatewayBuilder::default()
    }
}

/// A builder for [`AssociatedGateway`](crate::types::AssociatedGateway).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociatedGatewayBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::GatewayType>,
    pub(crate) owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
}
impl AssociatedGatewayBuilder {
    /// <p>The ID of the associated gateway.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the associated gateway.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the associated gateway.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The type of associated gateway.</p>
    pub fn r#type(mut self, input: crate::types::GatewayType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of associated gateway.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::GatewayType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of associated gateway.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::GatewayType> {
        &self.r#type
    }
    /// <p>The ID of the Amazon Web Services account that owns the associated virtual private gateway or transit gateway.</p>
    pub fn owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the associated virtual private gateway or transit gateway.</p>
    pub fn set_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_account = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the associated virtual private gateway or transit gateway.</p>
    pub fn get_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_account
    }
    /// <p>The Region where the associated gateway is located.</p>
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Region where the associated gateway is located.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The Region where the associated gateway is located.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// Consumes the builder and constructs a [`AssociatedGateway`](crate::types::AssociatedGateway).
    pub fn build(self) -> crate::types::AssociatedGateway {
        crate::types::AssociatedGateway {
            id: self.id,
            r#type: self.r#type,
            owner_account: self.owner_account,
            region: self.region,
        }
    }
}
