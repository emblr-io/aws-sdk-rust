// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Data describing a contact.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContactData {
    /// <p>UUID of a contact.</p>
    pub contact_id: ::std::option::Option<::std::string::String>,
    /// <p>ARN of a mission profile.</p>
    pub mission_profile_arn: ::std::option::Option<::std::string::String>,
    /// <p>ARN of a satellite.</p>
    pub satellite_arn: ::std::option::Option<::std::string::String>,
    /// <p>Start time of a contact in UTC.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>End time of a contact in UTC.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Amount of time prior to contact start you’d like to receive a CloudWatch event indicating an upcoming pass.</p>
    pub pre_pass_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Amount of time after a contact ends that you’d like to receive a CloudWatch event indicating the pass has finished.</p>
    pub post_pass_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Name of a ground station.</p>
    pub ground_station: ::std::option::Option<::std::string::String>,
    /// <p>Status of a contact.</p>
    pub contact_status: ::std::option::Option<crate::types::ContactStatus>,
    /// <p>Error message of a contact.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>Maximum elevation angle of a contact.</p>
    pub maximum_elevation: ::std::option::Option<crate::types::Elevation>,
    /// <p>Region of a contact.</p>
    pub region: ::std::option::Option<::std::string::String>,
    /// <p>Tags assigned to a contact.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Projected time in UTC your satellite will rise above the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub visibility_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Projected time in UTC your satellite will set below the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub visibility_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ContactData {
    /// <p>UUID of a contact.</p>
    pub fn contact_id(&self) -> ::std::option::Option<&str> {
        self.contact_id.as_deref()
    }
    /// <p>ARN of a mission profile.</p>
    pub fn mission_profile_arn(&self) -> ::std::option::Option<&str> {
        self.mission_profile_arn.as_deref()
    }
    /// <p>ARN of a satellite.</p>
    pub fn satellite_arn(&self) -> ::std::option::Option<&str> {
        self.satellite_arn.as_deref()
    }
    /// <p>Start time of a contact in UTC.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>End time of a contact in UTC.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>Amount of time prior to contact start you’d like to receive a CloudWatch event indicating an upcoming pass.</p>
    pub fn pre_pass_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.pre_pass_start_time.as_ref()
    }
    /// <p>Amount of time after a contact ends that you’d like to receive a CloudWatch event indicating the pass has finished.</p>
    pub fn post_pass_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.post_pass_end_time.as_ref()
    }
    /// <p>Name of a ground station.</p>
    pub fn ground_station(&self) -> ::std::option::Option<&str> {
        self.ground_station.as_deref()
    }
    /// <p>Status of a contact.</p>
    pub fn contact_status(&self) -> ::std::option::Option<&crate::types::ContactStatus> {
        self.contact_status.as_ref()
    }
    /// <p>Error message of a contact.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>Maximum elevation angle of a contact.</p>
    pub fn maximum_elevation(&self) -> ::std::option::Option<&crate::types::Elevation> {
        self.maximum_elevation.as_ref()
    }
    /// <p>Region of a contact.</p>
    pub fn region(&self) -> ::std::option::Option<&str> {
        self.region.as_deref()
    }
    /// <p>Tags assigned to a contact.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Projected time in UTC your satellite will rise above the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn visibility_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.visibility_start_time.as_ref()
    }
    /// <p>Projected time in UTC your satellite will set below the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn visibility_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.visibility_end_time.as_ref()
    }
}
impl ContactData {
    /// Creates a new builder-style object to manufacture [`ContactData`](crate::types::ContactData).
    pub fn builder() -> crate::types::builders::ContactDataBuilder {
        crate::types::builders::ContactDataBuilder::default()
    }
}

/// A builder for [`ContactData`](crate::types::ContactData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContactDataBuilder {
    pub(crate) contact_id: ::std::option::Option<::std::string::String>,
    pub(crate) mission_profile_arn: ::std::option::Option<::std::string::String>,
    pub(crate) satellite_arn: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) pre_pass_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) post_pass_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ground_station: ::std::option::Option<::std::string::String>,
    pub(crate) contact_status: ::std::option::Option<crate::types::ContactStatus>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) maximum_elevation: ::std::option::Option<crate::types::Elevation>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) visibility_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) visibility_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ContactDataBuilder {
    /// <p>UUID of a contact.</p>
    pub fn contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>UUID of a contact.</p>
    pub fn set_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_id = input;
        self
    }
    /// <p>UUID of a contact.</p>
    pub fn get_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_id
    }
    /// <p>ARN of a mission profile.</p>
    pub fn mission_profile_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mission_profile_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of a mission profile.</p>
    pub fn set_mission_profile_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mission_profile_arn = input;
        self
    }
    /// <p>ARN of a mission profile.</p>
    pub fn get_mission_profile_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.mission_profile_arn
    }
    /// <p>ARN of a satellite.</p>
    pub fn satellite_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.satellite_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of a satellite.</p>
    pub fn set_satellite_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.satellite_arn = input;
        self
    }
    /// <p>ARN of a satellite.</p>
    pub fn get_satellite_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.satellite_arn
    }
    /// <p>Start time of a contact in UTC.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Start time of a contact in UTC.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Start time of a contact in UTC.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>End time of a contact in UTC.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>End time of a contact in UTC.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>End time of a contact in UTC.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>Amount of time prior to contact start you’d like to receive a CloudWatch event indicating an upcoming pass.</p>
    pub fn pre_pass_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.pre_pass_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Amount of time prior to contact start you’d like to receive a CloudWatch event indicating an upcoming pass.</p>
    pub fn set_pre_pass_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.pre_pass_start_time = input;
        self
    }
    /// <p>Amount of time prior to contact start you’d like to receive a CloudWatch event indicating an upcoming pass.</p>
    pub fn get_pre_pass_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.pre_pass_start_time
    }
    /// <p>Amount of time after a contact ends that you’d like to receive a CloudWatch event indicating the pass has finished.</p>
    pub fn post_pass_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.post_pass_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Amount of time after a contact ends that you’d like to receive a CloudWatch event indicating the pass has finished.</p>
    pub fn set_post_pass_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.post_pass_end_time = input;
        self
    }
    /// <p>Amount of time after a contact ends that you’d like to receive a CloudWatch event indicating the pass has finished.</p>
    pub fn get_post_pass_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.post_pass_end_time
    }
    /// <p>Name of a ground station.</p>
    pub fn ground_station(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ground_station = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of a ground station.</p>
    pub fn set_ground_station(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ground_station = input;
        self
    }
    /// <p>Name of a ground station.</p>
    pub fn get_ground_station(&self) -> &::std::option::Option<::std::string::String> {
        &self.ground_station
    }
    /// <p>Status of a contact.</p>
    pub fn contact_status(mut self, input: crate::types::ContactStatus) -> Self {
        self.contact_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of a contact.</p>
    pub fn set_contact_status(mut self, input: ::std::option::Option<crate::types::ContactStatus>) -> Self {
        self.contact_status = input;
        self
    }
    /// <p>Status of a contact.</p>
    pub fn get_contact_status(&self) -> &::std::option::Option<crate::types::ContactStatus> {
        &self.contact_status
    }
    /// <p>Error message of a contact.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Error message of a contact.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>Error message of a contact.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>Maximum elevation angle of a contact.</p>
    pub fn maximum_elevation(mut self, input: crate::types::Elevation) -> Self {
        self.maximum_elevation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum elevation angle of a contact.</p>
    pub fn set_maximum_elevation(mut self, input: ::std::option::Option<crate::types::Elevation>) -> Self {
        self.maximum_elevation = input;
        self
    }
    /// <p>Maximum elevation angle of a contact.</p>
    pub fn get_maximum_elevation(&self) -> &::std::option::Option<crate::types::Elevation> {
        &self.maximum_elevation
    }
    /// <p>Region of a contact.</p>
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Region of a contact.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>Region of a contact.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags assigned to a contact.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags assigned to a contact.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags assigned to a contact.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Projected time in UTC your satellite will rise above the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn visibility_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.visibility_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Projected time in UTC your satellite will rise above the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn set_visibility_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.visibility_start_time = input;
        self
    }
    /// <p>Projected time in UTC your satellite will rise above the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn get_visibility_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.visibility_start_time
    }
    /// <p>Projected time in UTC your satellite will set below the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn visibility_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.visibility_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Projected time in UTC your satellite will set below the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn set_visibility_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.visibility_end_time = input;
        self
    }
    /// <p>Projected time in UTC your satellite will set below the <a href="https://docs.aws.amazon.com/ground-station/latest/ug/site-masks.html">receive mask</a>. This time is based on the satellite's current active ephemeris for future contacts and the ephemeris that was active during contact execution for completed contacts. <i>This field is not present for contacts with a <code>SCHEDULING</code> or <code>SCHEDULED</code> status.</i></p>
    pub fn get_visibility_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.visibility_end_time
    }
    /// Consumes the builder and constructs a [`ContactData`](crate::types::ContactData).
    pub fn build(self) -> crate::types::ContactData {
        crate::types::ContactData {
            contact_id: self.contact_id,
            mission_profile_arn: self.mission_profile_arn,
            satellite_arn: self.satellite_arn,
            start_time: self.start_time,
            end_time: self.end_time,
            pre_pass_start_time: self.pre_pass_start_time,
            post_pass_end_time: self.post_pass_end_time,
            ground_station: self.ground_station,
            contact_status: self.contact_status,
            error_message: self.error_message,
            maximum_elevation: self.maximum_elevation,
            region: self.region,
            tags: self.tags,
            visibility_start_time: self.visibility_start_time,
            visibility_end_time: self.visibility_end_time,
        }
    }
}
