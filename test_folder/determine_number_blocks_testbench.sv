`timescale 1ns/1ns
module determine_num_blocks_testbench();

    // input 
    logic [31:0] size;
    logic clk;
    //output
    logic [7:0] num_blocks, expected_value;
    logic[7:0] correct_num_blocks[19:0];                      // 20 rows of bytes
    logic[5:0] correct_num_blocks_idx, errors; 

    determine_number_blocks DUT(
        .size(size),
        .num_blocks(num_blocks)
    );

    // clk generation
    always begin 
        clk = 1;
        #5; 
        clk = 0;
        #5;
    end
    
    // file read and initial values
    initial begin 
        $readmemb("test_num_blocks.txt", correct_num_blocks);
        correct_num_blocks_idx = 0;
        size = 0;
        errors = 0;
    end

    // loading expected values
    always @(posedge clk) begin 
        #1;
        expected_value <= correct_num_blocks[correct_num_blocks_idx];
        correct_num_blocks_idx <= correct_num_blocks_idx + 1;
        size <= size + 5;
    end

    always @(negedge clk) begin 
        if(num_blocks != expected_value) begin 
            $display("Error: input = %b", size);
            $display("Error: output = %b (expected: %b)", num_blocks, expected_value);
            errors = errors + 1;
        end
        if(correct_num_blocks_idx == 6'd20) begin
            $display("%d tests completed with %d errors", correct_num_blocks_idx, errors);
            $finish;
        end
    end
endmodule

