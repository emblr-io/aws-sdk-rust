// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartFuotaTaskInput {
    /// <p>The ID of a FUOTA task.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The LoRaWAN information used to start a FUOTA task.</p>
    pub lo_ra_wan: ::std::option::Option<crate::types::LoRaWanStartFuotaTask>,
}
impl StartFuotaTaskInput {
    /// <p>The ID of a FUOTA task.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The LoRaWAN information used to start a FUOTA task.</p>
    pub fn lo_ra_wan(&self) -> ::std::option::Option<&crate::types::LoRaWanStartFuotaTask> {
        self.lo_ra_wan.as_ref()
    }
}
impl StartFuotaTaskInput {
    /// Creates a new builder-style object to manufacture [`StartFuotaTaskInput`](crate::operation::start_fuota_task::StartFuotaTaskInput).
    pub fn builder() -> crate::operation::start_fuota_task::builders::StartFuotaTaskInputBuilder {
        crate::operation::start_fuota_task::builders::StartFuotaTaskInputBuilder::default()
    }
}

/// A builder for [`StartFuotaTaskInput`](crate::operation::start_fuota_task::StartFuotaTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartFuotaTaskInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) lo_ra_wan: ::std::option::Option<crate::types::LoRaWanStartFuotaTask>,
}
impl StartFuotaTaskInputBuilder {
    /// <p>The ID of a FUOTA task.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of a FUOTA task.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of a FUOTA task.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The LoRaWAN information used to start a FUOTA task.</p>
    pub fn lo_ra_wan(mut self, input: crate::types::LoRaWanStartFuotaTask) -> Self {
        self.lo_ra_wan = ::std::option::Option::Some(input);
        self
    }
    /// <p>The LoRaWAN information used to start a FUOTA task.</p>
    pub fn set_lo_ra_wan(mut self, input: ::std::option::Option<crate::types::LoRaWanStartFuotaTask>) -> Self {
        self.lo_ra_wan = input;
        self
    }
    /// <p>The LoRaWAN information used to start a FUOTA task.</p>
    pub fn get_lo_ra_wan(&self) -> &::std::option::Option<crate::types::LoRaWanStartFuotaTask> {
        &self.lo_ra_wan
    }
    /// Consumes the builder and constructs a [`StartFuotaTaskInput`](crate::operation::start_fuota_task::StartFuotaTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_fuota_task::StartFuotaTaskInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_fuota_task::StartFuotaTaskInput {
            id: self.id,
            lo_ra_wan: self.lo_ra_wan,
        })
    }
}
