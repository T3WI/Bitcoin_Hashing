// TODO: Optimization. 7 ccs behind the desired max clock cycles. Precomputation of wt?
module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);


parameter num_nonces = 16;
parameter NUM_OF_WORDS = 32;
parameter WORDS_IN_BLOCK = 16;
parameter NUM_OF_HASH_CONSTANTS = 8;

enum logic [ 3:0] {IDLE, WAIT, READ, PHASE1, PHASE2P1, PHASE2P2, 
PHASE3P1, PHASE3P2, WRITE} state;
logic [15:0] offset; 
logic [31:0] message[NUM_OF_WORDS];  
logic [7:0]  i;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] h0_afterp1, h1_afterp1, h2_afterp1, h3_afterp1, h4_afterp1, 
h5_afterp1, h6_afterp1, h7_afterp1;
logic [31:0] h_afterp2_intermediate[0:7][0:7];  // temporary storage for output of phase 2
logic [31:0] h_afterp2[0:15][0:7];      // 16 nonces, h0-h7 (each 32 bits)
logic [31:0] h_afterp3[0:15][0:7];      // 16 nonces, h0-h7 (each 32 bits)
logic [31:0] w2[0:7][0:15];
logic start2; 
logic [7:0] done2;

logic[31:0] k[0:63] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};
logic [3:0] nonce_array[16] = '{
    4'd0,
    4'd1,
    4'd2, 
    4'd3,
    4'd4, 
    4'd5, 
    4'd6,
    4'd7, 
    4'd8, 
    4'd9,
    4'd10, 
    4'd11,
    4'd12,
    4'd13,
    4'd14,
    4'd15
};

// Student to add rest of the code here

assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;



always_ff@(posedge clk, negedge reset_n) 
begin 
    if(!reset_n) 
    begin 
        cur_we <= 1'b0;
        state <= IDLE;
    end
    else 
    begin 
        case(state)
            IDLE: 
            begin
                if(start) begin 
                    // init h7-h0
                    h0 <= 32'h6a09e667;
                    h1 <= 32'hbb67ae85;
                    h2 <= 32'h3c6ef372;
                    h3 <= 32'ha54ff53a;
                    h4 <= 32'h510e527f;
                    h5 <= 32'h9b05688c;
                    h6 <= 32'h1f83d9ab;
                    h7 <= 32'h5be0cd19;
                    cur_addr <= message_addr;
                    state <= WAIT;
                    offset <= 16'b0;
                    i <= 6'b0;
                end
                else begin 
                    state <= IDLE;
                end
            end
            WAIT: 
            begin
                // need to make sure the correct addresses are synched
                cur_addr <= cur_addr + 16'b1;  
                state <= READ;
            end
            // NOTE: message[19] is blank since w[3] in the 2nd message block
            // is reserved for the nonce
            
            READ:
            begin 
                if(offset < NUM_OF_WORDS - 1) begin 
                    message[offset] <= mem_read_data;
                    offset <= offset + 16'b1;
                    state <= READ;
                end
                // Why is offset changing in this else statement? 
                // Why are there several extra clock cycles beign consumed here?
                // I've tried just message[21] <= 32'b0, message[22] <= 32'b0,...
                // and it produces the same result
                else begin 
                    // put message[0]-message[15] in w
                    for(int k = 0; k < WORDS_IN_BLOCK; k++) 
                    begin
                        w2[0][k] <= message[k]; 
                    end
                    // padding
                    for(int j = 21; j < 31; j++)            
                    begin 
                        message[j] <= 32'b0;
                    end
                    message[20] <= {1'b1, {31{1'b0}}};
                    message[31] <= 32'd640;
                    // set digest
                    h0_afterp1 <= h0;
                    h1_afterp1 <= h1;
                    h2_afterp1 <= h2;
                    h3_afterp1 <= h3;
                    h4_afterp1 <= h4;
                    h5_afterp1 <= h5;
                    h6_afterp1 <= h6;
                    h7_afterp1 <= h7;
                    // set necessary variables
                    offset <= 16'b0;
                    start2 <= 1'b1;
                    state <= PHASE1;
                end
            end
            PHASE1:
            begin
                if(done2[0]) 
                begin 
                    // load h0-h7 to reg
                    h0_afterp1 <= h_afterp2_intermediate[0][0];
                    h1_afterp1 <= h_afterp2_intermediate[0][1];
                    h2_afterp1 <= h_afterp2_intermediate[0][2];
                    h3_afterp1 <= h_afterp2_intermediate[0][3];
                    h4_afterp1 <= h_afterp2_intermediate[0][4];
                    h5_afterp1 <= h_afterp2_intermediate[0][5];
                    h6_afterp1 <= h_afterp2_intermediate[0][6];
                    h7_afterp1 <= h_afterp2_intermediate[0][7];
                    // load new words into w
                    for(int nonce_block = 0; nonce_block < 8; nonce_block++)
                    begin
                        for(int index = 0; index < WORDS_IN_BLOCK; index++)
                        begin 
                            w2[nonce_block][index] <= (index == 3) ? nonce_array[nonce_block] : message[16 + index];
                        end 
                    end
                    
                    state <= PHASE2P1;
                end
                else 
                begin
                    state <= PHASE1;
                end 
            end
            
            PHASE2P1:
            begin 
                if(done2[0]) 
                begin 
                    // load h0-h7 for nonce = 0:7 into reg
                    for(int nonce_block = 0; nonce_block < 8; nonce_block++)
                    begin
                        for(int hx = 0; hx < 8; hx++)
                        begin 
                            h_afterp2[nonce_block][hx] <= h_afterp2_intermediate[nonce_block][hx];
                        end 
                    end
                    // load new words into w
                    for(int nonce_block = 8; nonce_block < num_nonces; nonce_block++)
                    begin
                        for(int index = 0; index < WORDS_IN_BLOCK; index++)
                        begin 
                            w2[nonce_block - 8][index] <= (index == 3) ? nonce_array[nonce_block] : message[16 + index];
                        end 
                    end
                    state <= PHASE2P2;
                end
                else 
                begin 
                    state <= PHASE2P1;
                end
            end

            PHASE2P2:
            begin 
                if(done2[0]) 
                begin 
                    // load h0-h7 for nonce = 8:15 into reg
                    for(int nonce_block = 8; nonce_block < num_nonces; nonce_block++)
                    begin
                        for(int hx = 0; hx < 8; hx++)
                        begin 
                            h_afterp2[nonce_block][hx] <= h_afterp2_intermediate[nonce_block - 8][hx];
                        end 
                    end
                    // Create new message block 
                    // logic [31:0] w3[0:7][0:15];
                    for(int nonce_block = 0; nonce_block < 8; nonce_block++) 
                    begin 
                        for(int index = 0; index < WORDS_IN_BLOCK; index++) 
                        begin
                            if(index < NUM_OF_HASH_CONSTANTS) 
                            begin 
                                w2[nonce_block][index] <= h_afterp2[nonce_block][index];
                            end
                            else if(index == NUM_OF_HASH_CONSTANTS) 
                            begin 
                                w2[nonce_block][index] <= {1'b1, {31{1'b0}}};
                            end
                            else if(index < WORDS_IN_BLOCK - 1) 
                            begin 
                                w2[nonce_block][index] <= 32'b0;
                            end
                            else 
                            begin 
                                w2[nonce_block][index] <= 32'd256;
                            end
                        end
                    end
                    h0_afterp1 <= h0;
                    h1_afterp1 <= h1;
                    h2_afterp1 <= h2;
                    h3_afterp1 <= h3;
                    h4_afterp1 <= h4;
                    h5_afterp1 <= h5;
                    h6_afterp1 <= h6;
                    h7_afterp1 <= h7;
                    state <= PHASE3P1;
                end
                else 
                begin 
                    state <= PHASE2P2;
                end
            end

            PHASE3P1:
            begin 
                if(done2[0])
                begin 
                    // load h0-h7 for nonce = 0:7 into reg
                    for(int nonce_block = 0; nonce_block < 8; nonce_block++)
                    begin
                        for(int hx = 0; hx < 8; hx++)
                        begin 
                            h_afterp3[nonce_block][hx] <= h_afterp2_intermediate[nonce_block][hx];
                        end 
                    end
                    // load new words into w
                    for(int nonce_block = 0; nonce_block < 8; nonce_block++)
                    begin
                        for(int index = 0; index < 8; index++)
                        begin 
                            w2[nonce_block][index] <= h_afterp2[nonce_block + 8][index];
                        end 
                    end
                    state <= PHASE3P2;
                end
                else 
                begin 
                    state <= PHASE3P1;
                end
            end

            PHASE3P2:
            begin 
                if(done2[0]) 
                begin 
                    // load h0-h7 for nonce = 8:15 into reg
                    for(int nonce_block = 8; nonce_block < num_nonces; nonce_block++)
                    begin
                        for(int hx = 0; hx < 8; hx++)
                        begin 
                            h_afterp3[nonce_block][hx] <= h_afterp2_intermediate[nonce_block - 8][hx];
                        end 
                    end
                    cur_we <= 1'b1;
                    state <= WRITE;
                end
                else 
                begin 
                    state <= PHASE3P2;
                end
                
            end

            WRITE: 
            begin 
                if(i <= 15) 
                begin 
                    state <= WRITE;
                    i <= i + 8'b1;
                    offset <= i;
                    cur_addr <= output_addr;
                    if(i == 0) cur_write_data <= h_afterp3[0][0];
                    else if(i == 1) cur_write_data <= h_afterp3[1][0];
                    else if(i == 2) cur_write_data <= h_afterp3[2][0];
                    else if(i == 3) cur_write_data <= h_afterp3[3][0];
                    else if(i == 4) cur_write_data <= h_afterp3[4][0];
                    else if(i == 5) cur_write_data <= h_afterp3[5][0];
                    else if(i == 6) cur_write_data <= h_afterp3[6][0];
                    else if(i == 7) cur_write_data <= h_afterp3[7][0];
                    else if(i == 8) cur_write_data <= h_afterp3[8][0];
                    else if(i == 9) cur_write_data <= h_afterp3[9][0];
                    else if(i == 10) cur_write_data <= h_afterp3[10][0];
                    else if(i == 11) cur_write_data <= h_afterp3[11][0];
                    else if(i == 12) cur_write_data <= h_afterp3[12][0];
                    else if(i == 13) cur_write_data <= h_afterp3[13][0];
                    else if(i == 14) cur_write_data <= h_afterp3[14][0];
                    else if(i == 15) cur_write_data <= h_afterp3[15][0];
                end
                else 
                begin 
                    offset <= 16'b0;
                    state <= IDLE;
                end
            end
        endcase
    end
end



// simplified_sha256 shasha1
// (
//     .clk(clk),
//     .reset_n(reset_n),
//     .start(start1),
//     .message(w1),
//     .g0(h0), .g1(h1), .g2(h2), .g3(h3), .g4(h4), .g5(h5), .g6(h6), .g7(h7),
//     .done(done1),
//     .h0(h0_after), .h1(h1_after), .h2(h2_after), .h3(h3_after), 
//     .h4(h4_after), .h5(h5_after), .h6(h6_after), .h7(h7_after),
//     .k(k)
// );


genvar p2;
generate
    for(p2 = 0; p2 < num_nonces/2; p2++) begin : phase2_sha256
        simplified_sha256 shasha2(
            .clk(clk),
            .reset_n(reset_n),
            .start(start2),
            .message(w2[p2]),       // nonce'd message from 0-7, and then 8-15 in the following iteration
            .g0(h0_afterp1), .g1(h1_afterp1), .g2(h2_afterp1), .g3(h3_afterp1), 
            .g4(h4_afterp1), .g5(h5_afterp1), .g6(h6_afterp1), .g7(h7_afterp1),
            .done(done2[p2]),
            .h0(h_afterp2_intermediate[p2][0]), .h1(h_afterp2_intermediate[p2][1]), .h2(h_afterp2_intermediate[p2][2]), .h3(h_afterp2_intermediate[p2][3]), 
            .h4(h_afterp2_intermediate[p2][4]), .h5(h_afterp2_intermediate[p2][5]), .h6(h_afterp2_intermediate[p2][6]), .h7(h_afterp2_intermediate[p2][7]),
            .k(k)
        );
    end
endgenerate

assign done = (state == IDLE);

endmodule
