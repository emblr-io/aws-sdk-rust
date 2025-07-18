// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutTelemetryRecordsInput {
    /// <p></p>
    pub telemetry_records: ::std::option::Option<::std::vec::Vec<crate::types::TelemetryRecord>>,
    /// <p></p>
    pub ec2_instance_id: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub hostname: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl PutTelemetryRecordsInput {
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.telemetry_records.is_none()`.
    pub fn telemetry_records(&self) -> &[crate::types::TelemetryRecord] {
        self.telemetry_records.as_deref().unwrap_or_default()
    }
    /// <p></p>
    pub fn ec2_instance_id(&self) -> ::std::option::Option<&str> {
        self.ec2_instance_id.as_deref()
    }
    /// <p></p>
    pub fn hostname(&self) -> ::std::option::Option<&str> {
        self.hostname.as_deref()
    }
    /// <p></p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl PutTelemetryRecordsInput {
    /// Creates a new builder-style object to manufacture [`PutTelemetryRecordsInput`](crate::operation::put_telemetry_records::PutTelemetryRecordsInput).
    pub fn builder() -> crate::operation::put_telemetry_records::builders::PutTelemetryRecordsInputBuilder {
        crate::operation::put_telemetry_records::builders::PutTelemetryRecordsInputBuilder::default()
    }
}

/// A builder for [`PutTelemetryRecordsInput`](crate::operation::put_telemetry_records::PutTelemetryRecordsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutTelemetryRecordsInputBuilder {
    pub(crate) telemetry_records: ::std::option::Option<::std::vec::Vec<crate::types::TelemetryRecord>>,
    pub(crate) ec2_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) hostname: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl PutTelemetryRecordsInputBuilder {
    /// Appends an item to `telemetry_records`.
    ///
    /// To override the contents of this collection use [`set_telemetry_records`](Self::set_telemetry_records).
    ///
    /// <p></p>
    pub fn telemetry_records(mut self, input: crate::types::TelemetryRecord) -> Self {
        let mut v = self.telemetry_records.unwrap_or_default();
        v.push(input);
        self.telemetry_records = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_telemetry_records(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TelemetryRecord>>) -> Self {
        self.telemetry_records = input;
        self
    }
    /// <p></p>
    pub fn get_telemetry_records(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TelemetryRecord>> {
        &self.telemetry_records
    }
    /// <p></p>
    pub fn ec2_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ec2_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_ec2_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ec2_instance_id = input;
        self
    }
    /// <p></p>
    pub fn get_ec2_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ec2_instance_id
    }
    /// <p></p>
    pub fn hostname(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hostname = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_hostname(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hostname = input;
        self
    }
    /// <p></p>
    pub fn get_hostname(&self) -> &::std::option::Option<::std::string::String> {
        &self.hostname
    }
    /// <p></p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p></p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`PutTelemetryRecordsInput`](crate::operation::put_telemetry_records::PutTelemetryRecordsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_telemetry_records::PutTelemetryRecordsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::put_telemetry_records::PutTelemetryRecordsInput {
            telemetry_records: self.telemetry_records,
            ec2_instance_id: self.ec2_instance_id,
            hostname: self.hostname,
            resource_arn: self.resource_arn,
        })
    }
}
