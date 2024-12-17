/*
    Name: Karlo Gregorio

    Explanation:
    To find the number of blocks the following calculation must be performed: 
    determine_num_blocks = ceil(size*32/512);
    This can be simplified to:
    determine_num_blocks = ceil(size/16);

    We need to only add 1 when size does not perfectly divide 16. The size 
    perfectly divides 16 when there are no nonzero bits in the 4 least 
    significant bits. Therefore, we can check if this happens by
    shifting size to the right by 4, and then back to the left by 
    4, and checking if it matches its original value.
*/



module determine_number_blocks (
    output logic [7:0] num_blocks, 
    input logic [31:0] size);

    
    assign num_blocks = ((size >> 4) << 4 == size) ? (size >> 4) : (size >> 4) + 1'b1;
endmodule