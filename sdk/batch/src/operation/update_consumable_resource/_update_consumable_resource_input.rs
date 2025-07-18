// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateConsumableResourceInput {
    /// <p>The name or ARN of the consumable resource to be updated.</p>
    pub consumable_resource: ::std::option::Option<::std::string::String>,
    /// <p>Indicates how the quantity of the consumable resource will be updated. Must be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>SET</code></p>
    /// <p>Sets the quantity of the resource to the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>ADD</code></p>
    /// <p>Increases the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>REMOVE</code></p>
    /// <p>Reduces the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// </ul>
    pub operation: ::std::option::Option<::std::string::String>,
    /// <p>The change in the total quantity of the consumable resource. The <code>operation</code> parameter determines whether the value specified here will be the new total quantity, or the amount by which the total quantity will be increased or reduced. Must be a non-negative value.</p>
    pub quantity: ::std::option::Option<i64>,
    /// <p>If this parameter is specified and two update requests with identical payloads and <code>clientToken</code>s are received, these requests are considered the same request and the second request is rejected. A <code>clientToken</code> is valid for 8 hours or until one hour after the consumable resource is deleted, whichever is less.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateConsumableResourceInput {
    /// <p>The name or ARN of the consumable resource to be updated.</p>
    pub fn consumable_resource(&self) -> ::std::option::Option<&str> {
        self.consumable_resource.as_deref()
    }
    /// <p>Indicates how the quantity of the consumable resource will be updated. Must be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>SET</code></p>
    /// <p>Sets the quantity of the resource to the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>ADD</code></p>
    /// <p>Increases the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>REMOVE</code></p>
    /// <p>Reduces the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// </ul>
    pub fn operation(&self) -> ::std::option::Option<&str> {
        self.operation.as_deref()
    }
    /// <p>The change in the total quantity of the consumable resource. The <code>operation</code> parameter determines whether the value specified here will be the new total quantity, or the amount by which the total quantity will be increased or reduced. Must be a non-negative value.</p>
    pub fn quantity(&self) -> ::std::option::Option<i64> {
        self.quantity
    }
    /// <p>If this parameter is specified and two update requests with identical payloads and <code>clientToken</code>s are received, these requests are considered the same request and the second request is rejected. A <code>clientToken</code> is valid for 8 hours or until one hour after the consumable resource is deleted, whichever is less.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl UpdateConsumableResourceInput {
    /// Creates a new builder-style object to manufacture [`UpdateConsumableResourceInput`](crate::operation::update_consumable_resource::UpdateConsumableResourceInput).
    pub fn builder() -> crate::operation::update_consumable_resource::builders::UpdateConsumableResourceInputBuilder {
        crate::operation::update_consumable_resource::builders::UpdateConsumableResourceInputBuilder::default()
    }
}

/// A builder for [`UpdateConsumableResourceInput`](crate::operation::update_consumable_resource::UpdateConsumableResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateConsumableResourceInputBuilder {
    pub(crate) consumable_resource: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<::std::string::String>,
    pub(crate) quantity: ::std::option::Option<i64>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateConsumableResourceInputBuilder {
    /// <p>The name or ARN of the consumable resource to be updated.</p>
    /// This field is required.
    pub fn consumable_resource(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumable_resource = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the consumable resource to be updated.</p>
    pub fn set_consumable_resource(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumable_resource = input;
        self
    }
    /// <p>The name or ARN of the consumable resource to be updated.</p>
    pub fn get_consumable_resource(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumable_resource
    }
    /// <p>Indicates how the quantity of the consumable resource will be updated. Must be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>SET</code></p>
    /// <p>Sets the quantity of the resource to the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>ADD</code></p>
    /// <p>Increases the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>REMOVE</code></p>
    /// <p>Reduces the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// </ul>
    pub fn operation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates how the quantity of the consumable resource will be updated. Must be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>SET</code></p>
    /// <p>Sets the quantity of the resource to the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>ADD</code></p>
    /// <p>Increases the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>REMOVE</code></p>
    /// <p>Reduces the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// </ul>
    pub fn set_operation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation = input;
        self
    }
    /// <p>Indicates how the quantity of the consumable resource will be updated. Must be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>SET</code></p>
    /// <p>Sets the quantity of the resource to the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>ADD</code></p>
    /// <p>Increases the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// <li>
    /// <p><code>REMOVE</code></p>
    /// <p>Reduces the quantity of the resource by the value specified by the <code>quantity</code> parameter.</p></li>
    /// </ul>
    pub fn get_operation(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation
    }
    /// <p>The change in the total quantity of the consumable resource. The <code>operation</code> parameter determines whether the value specified here will be the new total quantity, or the amount by which the total quantity will be increased or reduced. Must be a non-negative value.</p>
    pub fn quantity(mut self, input: i64) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The change in the total quantity of the consumable resource. The <code>operation</code> parameter determines whether the value specified here will be the new total quantity, or the amount by which the total quantity will be increased or reduced. Must be a non-negative value.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i64>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The change in the total quantity of the consumable resource. The <code>operation</code> parameter determines whether the value specified here will be the new total quantity, or the amount by which the total quantity will be increased or reduced. Must be a non-negative value.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i64> {
        &self.quantity
    }
    /// <p>If this parameter is specified and two update requests with identical payloads and <code>clientToken</code>s are received, these requests are considered the same request and the second request is rejected. A <code>clientToken</code> is valid for 8 hours or until one hour after the consumable resource is deleted, whichever is less.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If this parameter is specified and two update requests with identical payloads and <code>clientToken</code>s are received, these requests are considered the same request and the second request is rejected. A <code>clientToken</code> is valid for 8 hours or until one hour after the consumable resource is deleted, whichever is less.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>If this parameter is specified and two update requests with identical payloads and <code>clientToken</code>s are received, these requests are considered the same request and the second request is rejected. A <code>clientToken</code> is valid for 8 hours or until one hour after the consumable resource is deleted, whichever is less.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`UpdateConsumableResourceInput`](crate::operation::update_consumable_resource::UpdateConsumableResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_consumable_resource::UpdateConsumableResourceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_consumable_resource::UpdateConsumableResourceInput {
            consumable_resource: self.consumable_resource,
            operation: self.operation,
            quantity: self.quantity,
            client_token: self.client_token,
        })
    }
}
