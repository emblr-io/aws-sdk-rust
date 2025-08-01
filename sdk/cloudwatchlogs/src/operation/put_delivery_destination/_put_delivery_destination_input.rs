// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutDeliveryDestinationInput {
    /// <p>A name for this delivery destination. This name must be unique for all delivery destinations in your account.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The format for the logs that this delivery destination will receive.</p>
    pub output_format: ::std::option::Option<crate::types::OutputFormat>,
    /// <p>A structure that contains the ARN of the Amazon Web Services resource that will receive the logs.</p>
    pub delivery_destination_configuration: ::std::option::Option<crate::types::DeliveryDestinationConfiguration>,
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a></p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PutDeliveryDestinationInput {
    /// <p>A name for this delivery destination. This name must be unique for all delivery destinations in your account.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The format for the logs that this delivery destination will receive.</p>
    pub fn output_format(&self) -> ::std::option::Option<&crate::types::OutputFormat> {
        self.output_format.as_ref()
    }
    /// <p>A structure that contains the ARN of the Amazon Web Services resource that will receive the logs.</p>
    pub fn delivery_destination_configuration(&self) -> ::std::option::Option<&crate::types::DeliveryDestinationConfiguration> {
        self.delivery_destination_configuration.as_ref()
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a></p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl PutDeliveryDestinationInput {
    /// Creates a new builder-style object to manufacture [`PutDeliveryDestinationInput`](crate::operation::put_delivery_destination::PutDeliveryDestinationInput).
    pub fn builder() -> crate::operation::put_delivery_destination::builders::PutDeliveryDestinationInputBuilder {
        crate::operation::put_delivery_destination::builders::PutDeliveryDestinationInputBuilder::default()
    }
}

/// A builder for [`PutDeliveryDestinationInput`](crate::operation::put_delivery_destination::PutDeliveryDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutDeliveryDestinationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) output_format: ::std::option::Option<crate::types::OutputFormat>,
    pub(crate) delivery_destination_configuration: ::std::option::Option<crate::types::DeliveryDestinationConfiguration>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PutDeliveryDestinationInputBuilder {
    /// <p>A name for this delivery destination. This name must be unique for all delivery destinations in your account.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for this delivery destination. This name must be unique for all delivery destinations in your account.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for this delivery destination. This name must be unique for all delivery destinations in your account.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The format for the logs that this delivery destination will receive.</p>
    pub fn output_format(mut self, input: crate::types::OutputFormat) -> Self {
        self.output_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format for the logs that this delivery destination will receive.</p>
    pub fn set_output_format(mut self, input: ::std::option::Option<crate::types::OutputFormat>) -> Self {
        self.output_format = input;
        self
    }
    /// <p>The format for the logs that this delivery destination will receive.</p>
    pub fn get_output_format(&self) -> &::std::option::Option<crate::types::OutputFormat> {
        &self.output_format
    }
    /// <p>A structure that contains the ARN of the Amazon Web Services resource that will receive the logs.</p>
    /// This field is required.
    pub fn delivery_destination_configuration(mut self, input: crate::types::DeliveryDestinationConfiguration) -> Self {
        self.delivery_destination_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains the ARN of the Amazon Web Services resource that will receive the logs.</p>
    pub fn set_delivery_destination_configuration(mut self, input: ::std::option::Option<crate::types::DeliveryDestinationConfiguration>) -> Self {
        self.delivery_destination_configuration = input;
        self
    }
    /// <p>A structure that contains the ARN of the Amazon Web Services resource that will receive the logs.</p>
    pub fn get_delivery_destination_configuration(&self) -> &::std::option::Option<crate::types::DeliveryDestinationConfiguration> {
        &self.delivery_destination_configuration
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a></p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a></p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a></p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`PutDeliveryDestinationInput`](crate::operation::put_delivery_destination::PutDeliveryDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_delivery_destination::PutDeliveryDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_delivery_destination::PutDeliveryDestinationInput {
            name: self.name,
            output_format: self.output_format,
            delivery_destination_configuration: self.delivery_destination_configuration,
            tags: self.tags,
        })
    }
}
