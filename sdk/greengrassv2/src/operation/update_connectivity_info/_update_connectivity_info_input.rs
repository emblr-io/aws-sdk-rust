// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateConnectivityInfoInput {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub thing_name: ::std::option::Option<::std::string::String>,
    /// <p>The connectivity information for the core device.</p>
    pub connectivity_info: ::std::option::Option<::std::vec::Vec<crate::types::ConnectivityInfo>>,
}
impl UpdateConnectivityInfoInput {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn thing_name(&self) -> ::std::option::Option<&str> {
        self.thing_name.as_deref()
    }
    /// <p>The connectivity information for the core device.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.connectivity_info.is_none()`.
    pub fn connectivity_info(&self) -> &[crate::types::ConnectivityInfo] {
        self.connectivity_info.as_deref().unwrap_or_default()
    }
}
impl UpdateConnectivityInfoInput {
    /// Creates a new builder-style object to manufacture [`UpdateConnectivityInfoInput`](crate::operation::update_connectivity_info::UpdateConnectivityInfoInput).
    pub fn builder() -> crate::operation::update_connectivity_info::builders::UpdateConnectivityInfoInputBuilder {
        crate::operation::update_connectivity_info::builders::UpdateConnectivityInfoInputBuilder::default()
    }
}

/// A builder for [`UpdateConnectivityInfoInput`](crate::operation::update_connectivity_info::UpdateConnectivityInfoInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateConnectivityInfoInputBuilder {
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) connectivity_info: ::std::option::Option<::std::vec::Vec<crate::types::ConnectivityInfo>>,
}
impl UpdateConnectivityInfoInputBuilder {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    /// This field is required.
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// Appends an item to `connectivity_info`.
    ///
    /// To override the contents of this collection use [`set_connectivity_info`](Self::set_connectivity_info).
    ///
    /// <p>The connectivity information for the core device.</p>
    pub fn connectivity_info(mut self, input: crate::types::ConnectivityInfo) -> Self {
        let mut v = self.connectivity_info.unwrap_or_default();
        v.push(input);
        self.connectivity_info = ::std::option::Option::Some(v);
        self
    }
    /// <p>The connectivity information for the core device.</p>
    pub fn set_connectivity_info(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConnectivityInfo>>) -> Self {
        self.connectivity_info = input;
        self
    }
    /// <p>The connectivity information for the core device.</p>
    pub fn get_connectivity_info(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConnectivityInfo>> {
        &self.connectivity_info
    }
    /// Consumes the builder and constructs a [`UpdateConnectivityInfoInput`](crate::operation::update_connectivity_info::UpdateConnectivityInfoInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_connectivity_info::UpdateConnectivityInfoInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_connectivity_info::UpdateConnectivityInfoInput {
            thing_name: self.thing_name,
            connectivity_info: self.connectivity_info,
        })
    }
}
