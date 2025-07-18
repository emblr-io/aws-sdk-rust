// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`CreateOdbPeeringConnection`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`odb_network_id(impl Into<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::odb_network_id) / [`set_odb_network_id(Option<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::set_odb_network_id):<br>required: **true**<br><p>The unique identifier of the ODB network that initiates the peering connection.</p><br>
    ///   - [`peer_network_id(impl Into<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::peer_network_id) / [`set_peer_network_id(Option<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::set_peer_network_id):<br>required: **true**<br><p>The unique identifier of the peer network. This can be either a VPC ID or another ODB network ID.</p><br>
    ///   - [`display_name(impl Into<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::display_name) / [`set_display_name(Option<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::set_display_name):<br>required: **false**<br><p>The display name for the ODB peering connection.</p><br>
    ///   - [`client_token(impl Into<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::client_token) / [`set_client_token(Option<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::set_client_token):<br>required: **false**<br><p>The client token for the ODB peering connection request.</p> <p>Constraints:</p> <ul>  <li>   <p>Must be unique for each request.</p></li> </ul><br>
    ///   - [`tags(impl Into<String>, impl Into<String>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::tags) / [`set_tags(Option<HashMap::<String, String>>)`](crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::set_tags):<br>required: **false**<br><p>The tags to assign to the ODB peering connection.</p><br>
    /// - On success, responds with [`CreateOdbPeeringConnectionOutput`](crate::operation::create_odb_peering_connection::CreateOdbPeeringConnectionOutput) with field(s):
    ///   - [`display_name(Option<String>)`](crate::operation::create_odb_peering_connection::CreateOdbPeeringConnectionOutput::display_name): <p>The display name of the ODB peering connection.</p>
    ///   - [`status(Option<ResourceStatus>)`](crate::operation::create_odb_peering_connection::CreateOdbPeeringConnectionOutput::status): <p>The status of the ODB peering connection.</p> <p>Valid Values: <code>provisioning | active | terminating | terminated | failed</code></p>
    ///   - [`status_reason(Option<String>)`](crate::operation::create_odb_peering_connection::CreateOdbPeeringConnectionOutput::status_reason): <p>The reason for the current status of the ODB peering connection.</p>
    ///   - [`odb_peering_connection_id(String)`](crate::operation::create_odb_peering_connection::CreateOdbPeeringConnectionOutput::odb_peering_connection_id): <p>The unique identifier of the ODB peering connection.</p>
    /// - On failure, responds with [`SdkError<CreateOdbPeeringConnectionError>`](crate::operation::create_odb_peering_connection::CreateOdbPeeringConnectionError)
    pub fn create_odb_peering_connection(
        &self,
    ) -> crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder {
        crate::operation::create_odb_peering_connection::builders::CreateOdbPeeringConnectionFluentBuilder::new(self.handle.clone())
    }
}
